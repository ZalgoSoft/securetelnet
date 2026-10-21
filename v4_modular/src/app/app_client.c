#include "app.h"
#include "crypto/field.h"
#include "io.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#define h_addr h_addr_list[0] /* for backward compatibility */

#include "app.h"
#include "io.h"
#include "crypto/field.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

static int load_priv(const char *path, uint16_t *priv)
{
    FILE *f = fopen(path, "r");
    char line[128];
    unsigned v;
    if (!f) return -1;
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    fclose(f);
    if (sscanf(line, "%x", &v) != 1) return -1;
    *priv = (uint16_t)v;
    return 0;
}

static int client_auth(proto_ctx_t *p, session_t *s, crypto_ctx_t *c, uint16_t priv)
{
    uint8_t buf[8];
    size_t len = 2;
    uint16_t challenge;
    uint16_t out1, out2;
    if (proto_recv(p, buf, &len) != 0) return -1;
    session_note_rx(s);
    if (len != 2) return -1;
    challenge = (uint16_t)(buf[0] | ((uint16_t)buf[1] << 8));
    if (c->auth->client(c->kdf, p->secret, priv, challenge, &out1, &out2) != 0) return -1;
    if (strcmp(c->auth->name, "schnorr") == 0) {
        buf[0] = (uint8_t)(out1 & 0xFF);
        buf[1] = (uint8_t)((out1 >> 8) & 0xFF);
        buf[2] = (uint8_t)(out2 & 0xFF);
        buf[3] = (uint8_t)((out2 >> 8) & 0xFF);
        if (proto_send(p, buf, 4) != 0) return -1;
    } else {
        buf[0] = (uint8_t)(out1 & 0xFF);
        buf[1] = (uint8_t)((out1 >> 8) & 0xFF);
        if (proto_send(p, buf, 2) != 0) return -1;
    }
    session_note_tx(s);
    len = 2;
    if (proto_recv(p, buf, &len) != 0) return -1;
    session_note_rx(s);
    if (len == 2 && buf[0] == 'O' && buf[1] == 'K') {
        session_log(s, "auth ok");
        return 0;
    }
    session_log(s, "auth failed");
    return -1;
}

int app_run_client(const char *host, int port, const char *priv_key, app_config_t *cfg)
{
    int fd;
    struct sockaddr_in addr;
    struct hostent *he;
    uint8_t buf[8];
    uint16_t A, B, key_priv, dh_priv, nonce, peer_nonce, S;
    session_t *s;
    proto_ctx_t *p;
    negotiation_params_t srv;
    if (load_priv(priv_key, &key_priv) != 0) { fprintf(stderr, "cannot load %s\n", priv_key); return 1; }
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 1;
    he = gethostbyname(host);
    if (!he) { fprintf(stderr, "cannot resolve %s\n", host); close(fd); return 1; }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr, he->h_addr, (size_t)he->h_length);
    addr.sin_port = htons((uint16_t)port);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { close(fd); return 1; }
    if (negotiate_client(fd, &cfg->neg, &srv) != 0) { close(fd); return 1; }
    if (crypto_init(&cfg->crypto, negotiation_dh_name(srv.dh), negotiation_kdf_name(srv.kdf),
                    negotiation_cipher_name(srv.cipher), negotiation_mac_name(srv.mac),
                    negotiation_prng_name(srv.prng), negotiation_auth_name(srv.auth),
                    srv.schnorr_cache) != 0) { close(fd); return 1; }
    cfg->compress = compress_find(negotiation_compress_name(srv.compress));
    if (!cfg->compress) { close(fd); return 1; }
    if (cfg->crypto.dh->client(&A, &nonce, &dh_priv) != 0) { close(fd); return 1; }
    buf[0] = (uint8_t)(A & 0xFF);
    buf[1] = (uint8_t)((A >> 8) & 0xFF);
    buf[2] = (uint8_t)(nonce & 0xFF);
    buf[3] = (uint8_t)((nonce >> 8) & 0xFF);
    if (io_write_full(fd, buf, 4) != 4) { close(fd); return 1; }
    if (io_read_full(fd, buf, 4) != 4) { close(fd); return 1; }
    B = (uint16_t)(buf[0] | ((uint16_t)buf[1] << 8));
    peer_nonce = (uint16_t)(buf[2] | ((uint16_t)buf[3] << 8));
    (void)peer_nonce;
    if (B == 0 || B == 1 || B == crypto_P - 1 || B >= crypto_P) { close(fd); return 1; }
    S = crypto_modpow(B, dh_priv, crypto_P);
    s = session_new();
    session_set_secret(s, S);
    session_open_log(s, cfg->session_dir, "client", cfg->debug);
    session_log(s, "client session start");
    session_log(s, "negotiation ok dh=%s kdf=%s cipher=%s mac=%s prng=%s auth=%s compress=%s",
                negotiation_dh_name(srv.dh), negotiation_kdf_name(srv.kdf),
                negotiation_cipher_name(srv.cipher), negotiation_mac_name(srv.mac),
                negotiation_prng_name(srv.prng), negotiation_auth_name(srv.auth),
                negotiation_compress_name(srv.compress));
    session_log(s, "key exchange complete");
    p = proto_new(fd, &cfg->crypto, cfg->compress, S);
    if (client_auth(p, s, &cfg->crypto, key_priv) != 0) {
        proto_free(p); session_free(s); close(fd); return 1;
    }
    cfg->mode->client(p, s, &cfg->mode_args);
    session_log(s, "session end tx=%u rx=%u", s->tx_count, s->rx_count);
    proto_free(p);
    session_free(s);
    close(fd);
    return 0;
}
