#include "app.h"
#include "crypto/field.h"
#include "proto.h"
#include "io.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "app.h"
#include "crypto/field.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

static int load_keys(const char *path, uint16_t *keys, int max)
{
    FILE *f = fopen(path, "r");
    char line[256];
    int n = 0;
    if (!f) return -1;
    while (n < max && fgets(line, sizeof(line), f)) {
        unsigned v;
        if (sscanf(line, "%x", &v) == 1) keys[n++] = (uint16_t)v;
    }
    fclose(f);
    return n;
}

static int server_auth(proto_ctx_t *p, session_t *s, crypto_ctx_t *c, const uint16_t *keys, int nkeys)
{
    uint8_t buf[8];
    size_t len = 2;
    uint16_t challenge;
    if (c->auth->server(c->kdf, p->secret, 0, &challenge) != 0) return -1;
    buf[0] = (uint8_t)(challenge & 0xFF);
    buf[1] = (uint8_t)((challenge >> 8) & 0xFF);
    if (proto_send(p, buf, 2) != 0) return -1;
    session_note_tx(s);
    len = 4;
    if (proto_recv(p, buf, &len) != 0) return -1;
    session_note_rx(s);
    if (len == 2) {
        uint16_t tag = (uint16_t)(buf[0] | ((uint16_t)buf[1] << 8));
        int i;
        for (i = 0; i < nkeys; i++) {
            uint16_t expect = c->kdf->ks16(p->secret, (uint16_t)(keys[i] ^ challenge));
            if (tag == expect) {
                if (proto_send(p, (const uint8_t *)"OK", 2) != 0) return -1;
                session_note_tx(s);
                session_log(s, "auth ok");
                return 0;
            }
        }
    } else if (len == 4) {
        uint16_t R = (uint16_t)(buf[0] | ((uint16_t)buf[1] << 8));
        uint16_t sv = (uint16_t)(buf[2] | ((uint16_t)buf[3] << 8));
        int i;
        for (i = 0; i < nkeys; i++) {
            if (crypto_auth_schnorr_verify(p->secret, keys[i], challenge, R, sv) == 0) {
                if (proto_send(p, (const uint8_t *)"OK", 2) != 0) return -1;
                session_note_tx(s);
                session_log(s, "auth ok");
                return 0;
            }
        }
    }
    if (proto_send(p, (const uint8_t *)"NK", 2) != 0) return -1;
    session_note_tx(s);
    session_log(s, "auth failed");
    return -1;
}

int app_run_server(int listen_port, const char *auth_keys, app_config_t *cfg)
{
    int sfd, cfd;
    struct sockaddr_in addr;
    socklen_t alen = sizeof(addr);
    uint16_t keys[64];
    int nkeys;
    session_t *s;
    proto_ctx_t *p;
    negotiation_params_t peer;
    uint8_t buf[8];
    uint16_t A, B, priv, nonce, S;
    nkeys = load_keys(auth_keys, keys, 64);
    if (nkeys <= 0) { fprintf(stderr, "no keys in %s\n", auth_keys); return 1; }
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) return 1;
    {
        int one = 1;
        setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)listen_port);
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { close(sfd); return 1; }
    if (listen(sfd, 1) != 0) { close(sfd); return 1; }
    cfd = accept(sfd, (struct sockaddr *)&addr, &alen);
    close(sfd);
    if (cfd < 0) return 1;
    if (negotiate_server(cfd, &cfg->neg, &peer) != 0) { close(cfd); return 1; }
    if (crypto_init(&cfg->crypto, negotiation_dh_name(peer.dh), negotiation_kdf_name(peer.kdf),
                    negotiation_cipher_name(peer.cipher), negotiation_mac_name(peer.mac),
                    negotiation_prng_name(peer.prng), negotiation_auth_name(peer.auth),
                    peer.schnorr_cache) != 0) { close(cfd); return 1; }
    cfg->compress = compress_find(negotiation_compress_name(peer.compress));
    if (!cfg->compress) { close(cfd); return 1; }
    if (io_read_full(cfd, buf, 4) != 4) { close(cfd); return 1; }
    A = (uint16_t)(buf[0] | ((uint16_t)buf[1] << 8));
    if (cfg->crypto.dh->server(A, &B, &nonce, &priv) != 0) { close(cfd); return 1; }
    S = crypto_modpow(A, priv, crypto_P);
    buf[0] = (uint8_t)(B & 0xFF);
    buf[1] = (uint8_t)((B >> 8) & 0xFF);
    buf[2] = (uint8_t)(nonce & 0xFF);
    buf[3] = (uint8_t)((nonce >> 8) & 0xFF);
    if (io_write_full(cfd, buf, 4) != 4) { close(cfd); return 1; }
    s = session_new();
    session_set_secret(s, S);
    session_open_log(s, cfg->session_dir, "server", cfg->debug);
    session_log(s, "server session start");
    session_log(s, "negotiation ok dh=%s kdf=%s cipher=%s mac=%s prng=%s auth=%s compress=%s",
                negotiation_dh_name(peer.dh), negotiation_kdf_name(peer.kdf),
                negotiation_cipher_name(peer.cipher), negotiation_mac_name(peer.mac),
                negotiation_prng_name(peer.prng), negotiation_auth_name(peer.auth),
                negotiation_compress_name(peer.compress));
    session_log(s, "key exchange complete");
    p = proto_new(cfd, &cfg->crypto, cfg->compress, S);
    if (server_auth(p, s, &cfg->crypto, keys, nkeys) != 0) {
        proto_free(p); session_free(s); close(cfd); return 1;
    }
    cfg->mode->server(p, s, &cfg->mode_args);
    session_log(s, "session end tx=%u rx=%u", s->tx_count, s->rx_count);
    proto_free(p);
    session_free(s);
    close(cfd);
    return 0;
}
