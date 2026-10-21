#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define P 65519UL
#define D_INV 43679UL
#define MAX_KEYS 16
#define NONCE_LEN 4

static uint16_t G = 0;
static int g_debug = 0;

static void dbg(const char *fmt, ...) {
    if (!g_debug) return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[dbg] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static uint16_t modpow(uint16_t base, uint32_t exp) {
    uint32_t result = 1;
    uint32_t b = base % P;
    while (exp) {
        if (exp & 1) result = (result * b) % P;
        b = (b * b) % P;
        exp >>= 1;
    }
    return (uint16_t)result;
}

static uint32_t xorshift32(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    *state = x;
    return x;
}

static void fill_random(uint8_t *buf, size_t n, uint32_t *seed) {
    for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)(xorshift32(seed) >> 24);
}

static int read_full(int fd, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (uint8_t*)buf + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

static int write_full(int fd, const void *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, (const uint8_t*)buf + sent, n - sent);
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

static uint16_t ks16(uint16_t S, uint16_t counter) {
    uint32_t x = ((uint32_t)S ^ counter) | 1;
    x %= P;
    uint32_t x2 = (x * x) % P;
    return (uint16_t)((x2 * x) % P);
}

static uint8_t ks_byte(uint16_t S, uint16_t ctr, uint8_t i) {
    uint16_t v = ks16(S, (uint16_t)(ctr + i));
    return (uint8_t)(v ^ (v >> 8));
}

static void stream_xor(uint8_t *buf, size_t n, uint16_t S, uint16_t ctr) {
    for (size_t i = 0; i < n; i++)
        buf[i] ^= ks_byte(S, ctr, (uint8_t)i);
}

static void hexdump(const char *label, const uint8_t *buf, size_t n) {
    if (!g_debug) return;
    fprintf(stderr, "[dbg] %s (%zu bytes):", label, n);
    for (size_t i = 0; i < n; i++) fprintf(stderr, " %02x", buf[i]);
    fprintf(stderr, "\n");
}

static void schnorr_prove(uint16_t priv, uint16_t c,
                          uint16_t *R_out, uint16_t *s_out,
                          uint32_t *seed) {
    uint16_t r = (uint16_t)(1 + (xorshift32(seed) % (P - 2)));
    uint16_t R = modpow(G, r);
    uint32_t cs = ((uint32_t)c * priv) % (P - 1);
    uint16_t s = (uint16_t)(((uint32_t)r + cs) % (P - 1));
    dbg("schnorr_prove: priv=%04x c=%04x r=%04x R=%04x cs=%u s=%04x",
        priv, c, r, R, cs, s);
    *R_out = R;
    *s_out = s;
}

static int schnorr_verify(uint16_t pub, uint16_t c, uint16_t R, uint16_t s) {
    uint16_t lhs = modpow(G, s);
    uint16_t rhs = (uint16_t)(((uint32_t)R * modpow(pub, c)) % P);
    dbg("schnorr_verify: pub=%04x c=%04x R=%04x s=%04x lhs=%04x rhs=%04x -> %s",
        pub, c, R, s, lhs, rhs, lhs == rhs ? "OK" : "FAIL");
    return lhs == rhs;
}

static int handshake_client(int fd, uint16_t *S_out, uint32_t *ctr_out, uint32_t *seed) {
    uint16_t a = (uint16_t)(1 + (xorshift32(seed) % (P - 2)));
    uint16_t A = modpow(G, a);
    uint8_t nonce[NONCE_LEN]; fill_random(nonce, NONCE_LEN, seed);

    dbg("handshake_client: a=%04x A=%04x nonce=%02x%02x%02x%02x",
        a, A, nonce[0], nonce[1], nonce[2], nonce[3]);

    uint8_t pkt[2 + NONCE_LEN];
    pkt[0] = A & 0xFF; pkt[1] = A >> 8;
    memcpy(pkt + 2, nonce, NONCE_LEN);
    hexdump("handshake_client tx", pkt, sizeof(pkt));
    if (write_full(fd, pkt, sizeof(pkt)) < 0) return -1;

    uint8_t resp[2 + NONCE_LEN];
    if (read_full(fd, resp, sizeof(resp)) < 0) return -1;
    hexdump("handshake_client rx", resp, sizeof(resp));
    uint16_t B = (uint16_t)(resp[0] | (resp[1] << 8));
    uint32_t peer_nonce = 0;
    for (int i = 0; i < NONCE_LEN; i++) peer_nonce = (peer_nonce << 8) | resp[2 + i];

    if (B == 0 || B >= P) { dbg("handshake_client: bad B=%04x", B); return -1; }
    *S_out = modpow(B, a);
    *ctr_out = peer_nonce;
    dbg("handshake_client: B=%04x peer_nonce=%08x S=%04x", B, peer_nonce, *S_out);
    return 0;
}

static int handshake_server(int fd, uint16_t *S_out, uint32_t *ctr_out, uint32_t *seed) {
    uint8_t pkt[2 + NONCE_LEN];
    if (read_full(fd, pkt, sizeof(pkt)) < 0) return -1;
    hexdump("handshake_server rx", pkt, sizeof(pkt));
    uint16_t A = (uint16_t)(pkt[0] | (pkt[1] << 8));
    if (A == 0 || A >= P) { dbg("handshake_server: bad A=%04x", A); return -1; }

    uint16_t b = (uint16_t)(1 + (xorshift32(seed) % (P - 2)));
    uint16_t B = modpow(G, b);
    uint8_t nonce[NONCE_LEN]; fill_random(nonce, NONCE_LEN, seed);
    dbg("handshake_server: A=%04x b=%04x B=%04x nonce=%02x%02x%02x%02x",
        A, b, B, nonce[0], nonce[1], nonce[2], nonce[3]);

    uint8_t resp[2 + NONCE_LEN];
    resp[0] = B & 0xFF; resp[1] = B >> 8;
    memcpy(resp + 2, nonce, NONCE_LEN);
    hexdump("handshake_server tx", resp, sizeof(resp));
    if (write_full(fd, resp, sizeof(resp)) < 0) return -1;

    uint32_t peer_nonce = 0;
    for (int i = 0; i < NONCE_LEN; i++) peer_nonce = (peer_nonce << 8) | pkt[2 + i];

    *S_out = modpow(A, b);
    *ctr_out = peer_nonce;
    dbg("handshake_server: peer_nonce=%08x S=%04x", peer_nonce, *S_out);
    return 0;
}

static int auth_server_key(int fd, const uint16_t *keys, int nkeys, uint16_t S, uint32_t *seed) {
    uint16_t rnd = (uint16_t)(xorshift32(seed) & 0xFFFF);
    uint16_t c = (uint16_t)(ks16(S, rnd) ^ 0xFFFF);
    dbg("auth_server_key: rnd=%04x c=%04x nkeys=%d", rnd, c, nkeys);
    uint8_t pkt[2] = { c & 0xFF, c >> 8 };
    hexdump("auth_server_key tx challenge", pkt, 2);
    if (write_full(fd, pkt, 2) < 0) return -1;

    uint8_t resp[4];
    if (read_full(fd, resp, 4) < 0) return -1;
    hexdump("auth_server_key rx proof", resp, 4);
    uint16_t R = (uint16_t)(resp[0] | (resp[1] << 8));
    uint16_t s = (uint16_t)(resp[2] | (resp[3] << 8));
    dbg("auth_server_key: R=%04x s=%04x", R, s);

    int ok = 0;
    for (int i = 0; i < nkeys; i++) {
        dbg("auth_server_key: trying key[%d]=%04x", i, keys[i]);
        if (schnorr_verify(keys[i], c, R, s)) { ok = 1; break; }
    }

    uint8_t r[2] = { ok ? 'O' : 'N', 'K' };
    hexdump("auth_server_key tx result", r, 2);
    if (write_full(fd, r, 2) < 0) return -1;
    dbg("auth_server_key: %s", ok ? "OK" : "NOK");
    return ok ? 0 : -1;
}

static int auth_client_key(int fd, uint16_t priv, uint32_t *seed) {
    uint8_t pkt[2];
    if (read_full(fd, pkt, 2) < 0) return -1;
    hexdump("auth_client_key rx challenge", pkt, 2);
    uint16_t c = (uint16_t)(pkt[0] | (pkt[1] << 8));
    dbg("auth_client_key: priv=%04x c=%04x", priv, c);

    uint16_t R, s;
    schnorr_prove(priv, c, &R, &s, seed);

    uint8_t resp[4] = { R & 0xFF, R >> 8, s & 0xFF, s >> 8 };
    hexdump("auth_client_key tx proof", resp, 4);
    if (write_full(fd, resp, 4) < 0) return -1;

    uint8_t ok[2];
    if (read_full(fd, ok, 2) < 0) return -1;
    hexdump("auth_client_key rx result", ok, 2);
    int r = (ok[0] == 'O' && ok[1] == 'K') ? 0 : -1;
    dbg("auth_client_key: %s", r == 0 ? "OK" : "NOK");
    return r;
}

static int send_packet(int fd, const uint8_t *data, uint16_t len, uint16_t S, uint16_t *ctr) {
    uint8_t pkt[4 + 65535 + 2];
    uint16_t c = *ctr;
    pkt[0] = c & 0xFF; pkt[1] = c >> 8;
    pkt[2] = len & 0xFF; pkt[3] = len >> 8;
    memcpy(pkt + 4, data, len);
    dbg("send_packet: ctr=%04x len=%u S=%04x", c, len, S);
    hexdump("send_packet plaintext", data, len);
    stream_xor(pkt + 4, len, S, c);
    hexdump("send_packet ciphertext", pkt + 4, len);
    uint16_t tag = ks16(S, (uint16_t)(c ^ 0xFFFF));
    pkt[4 + len] = tag & 0xFF;
    pkt[4 + len + 1] = tag >> 8;
    hexdump("send_packet full", pkt, 4 + len + 2);
    if (write_full(fd, pkt, 4 + len + 2) < 0) return -1;
    *ctr = c + 1;
    return 0;
}

static int recv_packet(int fd, uint8_t *out, uint16_t *out_len, uint16_t S, uint16_t *ctr) {
    uint8_t hdr[4];
    if (read_full(fd, hdr, 4) < 0) return -1;
    hexdump("recv_packet hdr", hdr, 4);
    uint16_t c = (uint16_t)(hdr[0] | (hdr[1] << 8));
    uint16_t len = (uint16_t)(hdr[2] | (hdr[3] << 8));
    dbg("recv_packet: ctr=%04x len=%u expected_ctr=%04x", c, len, *ctr);
    if (read_full(fd, out, len + 2) < 0) return -1;
    hexdump("recv_packet body", out, len + 2);
    uint16_t tag = (uint16_t)(out[len] | (out[len + 1] << 8));
    uint16_t expect = ks16(S, (uint16_t)(c ^ 0xFFFF));
    dbg("recv_packet: tag=%04x expect=%04x", tag, expect);
    if (tag != expect) { fprintf(stderr, "MAC mismatch!\n"); return -1; }
    stream_xor(out, len, S, c);
    hexdump("recv_packet plaintext", out, len);
    *out_len = len;
    *ctr = c + 1;
    return 0;
}

static int load_keys(const char *path, uint16_t *keys, int max) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int n = 0;
    unsigned int v;
    while (n < max && fscanf(f, "%x", &v) == 1) {
        keys[n++] = (uint16_t)(v & 0xFFFF);
    }
    fclose(f);
    dbg("load_keys: loaded %d key(s) from %s", n, path);
    for (int i = 0; i < n; i++) dbg("load_keys: key[%d]=%04x", i, keys[i]);
    return n;
}

static int keygen(const char *privpath, const char *pubpath) {
    uint32_t seed = (uint32_t)time(NULL) ^ (uint32_t)getpid();
    dbg("keygen: seed=%08x", seed);
    uint16_t priv = (uint16_t)(1 + (xorshift32(&seed) % (P - 2)));
    uint16_t pub  = modpow(G, priv);
    dbg("keygen: priv=%04x pub=%04x (G=%u P=%lu)", priv, pub, G, P);
    FILE *f = fopen(privpath, "w");
    if (!f) { perror("fopen priv"); return 1; }
    fprintf(f, "%04X\n", priv);
    fclose(f);
    f = fopen(pubpath, "w");
    if (!f) { perror("fopen pub"); return 1; }
    fprintf(f, "%04X\n", pub);
    fclose(f);
    printf("priv = %04X -> %s\n", priv, privpath);
    printf("pub  = %04X -> %s\n", pub, pubpath);
    return 0;
}

static int load_priv(const char *path, uint16_t *priv) {
    FILE *f = fopen(path, "r");
    if (!f) { perror("fopen priv"); return -1; }
    unsigned int v;
    int r = fscanf(f, "%x", &v);
    fclose(f);
    if (r != 1) return -1;
    *priv = (uint16_t)(v & 0xFFFF);
    dbg("load_priv: %s -> priv=%04x", path, *priv);
    return 0;
}

static int run_server(int port, const char *keyfile) {
    uint16_t keys[MAX_KEYS];
    int nkeys = load_keys(keyfile, keys, MAX_KEYS);
    if (nkeys == 0) { fprintf(stderr, "no keys in %s\n", keyfile); return 1; }

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);
    if (bind(sfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(sfd, 1) < 0) { perror("listen"); return 1; }
    printf("server: listening on %d, %d key(s) loaded\n", port, nkeys);

    int cfd = accept(sfd, NULL, NULL);
    if (cfd < 0) { perror("accept"); return 1; }
    printf("server: client connected\n");

    uint32_t seed = (uint32_t)time(NULL) ^ (uint32_t)getpid();
    dbg("run_server: seed=%08x", seed);
    uint16_t S; uint32_t ctr32;
    if (handshake_server(cfd, &S, &ctr32, &seed) < 0) { fprintf(stderr, "handshake failed\n"); return 1; }
    uint16_t ctr = (uint16_t)ctr32;

    if (auth_server_key(cfd, keys, nkeys, S, &seed) < 0) {
        fprintf(stderr, "auth failed\n");
        close(cfd); close(sfd);
        return 1;
    }
    printf("server: auth OK, S=%u\n", S);

    fd_set rfds;
    char line[512];
    uint8_t in[1024];
    uint16_t inlen;

    for (;;) {
        FD_ZERO(&rfds);
        FD_SET(cfd, &rfds);
        FD_SET(STDIN_FILENO, &rfds);
        int maxfd = cfd > STDIN_FILENO ? cfd : STDIN_FILENO;
        int rv = select(maxfd + 1, &rfds, NULL, NULL, NULL);
        if (rv < 0) { perror("select"); break; }

        if (FD_ISSET(cfd, &rfds)) {
            if (recv_packet(cfd, in, &inlen, S, &ctr) < 0) break;
            in[inlen] = 0;
            printf("client> %s\n", in);
            fflush(stdout);
        }
        if (FD_ISSET(STDIN_FILENO, &rfds)) {
            if (!fgets(line, sizeof(line), stdin)) break;
            size_t n = strlen(line);
            if (n && line[n-1] == '\n') line[--n] = 0;
            if (send_packet(cfd, (uint8_t*)line, (uint16_t)n, S, &ctr) < 0) break;
        }
    }
    close(cfd); close(sfd);
    return 0;
}

static int run_client(const char *host, int port, const char *privfile) {
    uint16_t priv;
    if (load_priv(privfile, &priv) < 0) return 1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) { fprintf(stderr, "bad host\n"); return 1; }
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("connect"); return 1; }
    dbg("run_client: connected to %s:%d", host, port);

    uint32_t seed = (uint32_t)time(NULL) ^ (uint32_t)getpid() ^ 0xA5A5A5A5u;
    dbg("run_client: seed=%08x", seed);
    uint16_t S; uint32_t ctr32;
    if (handshake_client(fd, &S, &ctr32, &seed) < 0) { fprintf(stderr, "handshake failed\n"); return 1; }
    uint16_t ctr = (uint16_t)ctr32;

    if (auth_client_key(fd, priv, &seed) < 0) {
        fprintf(stderr, "auth failed\n");
        close(fd);
        return 1;
    }
    printf("client: auth OK, S=%u\n", S);

    fd_set rfds;
    char line[512];
    uint8_t in[1024];
    uint16_t inlen;

    for (;;) {
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        FD_SET(STDIN_FILENO, &rfds);
        int maxfd = fd > STDIN_FILENO ? fd : STDIN_FILENO;
        int rv = select(maxfd + 1, &rfds, NULL, NULL, NULL);
        if (rv < 0) { perror("select"); break; }

        if (FD_ISSET(fd, &rfds)) {
            if (recv_packet(fd, in, &inlen, S, &ctr) < 0) break;
            in[inlen] = 0;
            printf("server> %s\n", in);
            fflush(stdout);
        }
        if (FD_ISSET(STDIN_FILENO, &rfds)) {
            if (!fgets(line, sizeof(line), stdin)) break;
            size_t n = strlen(line);
            if (n && line[n-1] == '\n') line[--n] = 0;
            if (send_packet(fd, (uint8_t*)line, (uint16_t)n, S, &ctr) < 0) break;
        }
    }
    close(fd);
    return 0;
}

static uint16_t find_generator(void) {
    uint32_t qs[] = {2, 7, 31, 151};
    for (uint16_t g = 2; g < 100; g++) {
        int ok = 1;
        for (int i = 0; i < 4; i++)
            if (modpow(g, (P - 1) / qs[i]) == 1) { ok = 0; break; }
        if (ok) return g;
    }
    return 0;
}

static int self_test(void) {
    if ((P - 1) % 3 == 0) { fprintf(stderr, "self-test: p-1 div by 3\n"); return 1; }
    if ((3UL * D_INV) % (P - 1) != 1) { fprintf(stderr, "self-test: D_INV\n"); return 1; }
    G = find_generator();
    if (G == 0) { fprintf(stderr, "self-test: no generator\n"); return 1; }
    for (uint16_t x = 1; x < 100; x++) {
        uint16_t y = (uint16_t)(((uint32_t)x * x % P) * x % P);
        if (modpow(y, D_INV) != x) { fprintf(stderr, "self-test: cube inv %u\n", x); return 1; }
    }
    printf("self-test OK: G=%u\n", G);
    return 0;
}

static int run_tests(void) {
    int fails = 0;

    if (modpow(G, 0) != 1) { printf("FAIL modpow exp0\n"); fails++; }
    if (modpow(G, 1) != G) { printf("FAIL modpow exp1\n"); fails++; }
    if (modpow(G, P - 1) != 1) { printf("FAIL modpow Fermat\n"); fails++; }

    {
        uint32_t sd = 11111;
        for (int i = 0; i < 1000; i++) {
            uint16_t a = (uint16_t)(1 + (xorshift32(&sd) % (P - 2)));
            uint16_t b = (uint16_t)(1 + (xorshift32(&sd) % (P - 2)));
            uint16_t A = modpow(G, a), B = modpow(G, b);
            if (modpow(B, a) != modpow(A, b)) { printf("FAIL DH sym\n"); fails++; break; }
        }
    }

    {
        uint32_t sd = 22222;
        for (int i = 0; i < 1000; i++) {
            uint16_t priv = (uint16_t)(1 + (xorshift32(&sd) % (P - 2)));
            uint16_t pub = modpow(G, priv);
            uint16_t c = (uint16_t)(xorshift32(&sd) & 0xFFFF);
            uint16_t R, s;
            schnorr_prove(priv, c, &R, &s, &sd);
            if (!schnorr_verify(pub, c, R, s)) { printf("FAIL Schnorr valid\n"); fails++; break; }
        }
    }

    {
        uint16_t priv = 1234, pub = modpow(G, priv);
        uint16_t c = 0xABCD, R, s;
        uint32_t sd = 7;
        schnorr_prove(priv, c, &R, &s, &sd);
        if (schnorr_verify(pub, c ^ 1, R, s)) { printf("FAIL Schnorr bad c\n"); fails++; }
        if (schnorr_verify(pub, c, R ^ 1, s)) { printf("FAIL Schnorr bad R\n"); fails++; }
        if (schnorr_verify(pub, c, R, (uint16_t)(s + 1))) { printf("FAIL Schnorr bad s\n"); fails++; }
        if (schnorr_verify(modpow(G, priv + 1), c, R, s)) { printf("FAIL Schnorr bad pub\n"); fails++; }
    }

{
    uint32_t sd = 33333;
    int coll = 0;
    for (int i = 0; i < 1000; i++) {
        uint16_t S1 = (uint16_t)(xorshift32(&sd) & 0xFFFF);
        uint16_t c1 = (uint16_t)(xorshift32(&sd) & 0xFFFF);
        uint16_t c2 = (uint16_t)(xorshift32(&sd) & 0xFFFF);
        if (c1 != c2 && ks16(S1, c1) == ks16(S1, c2)) coll++;
    }
    if (coll > 0) { printf("FAIL ks16 collisions: %d\n", coll); fails++; }
}
{
    uint16_t S1 = 0x1235;
    uint16_t v0 = ks16(S1, 0);
    if (v0 != ks16(S1, 0)) { printf("FAIL ks16 determ\n"); fails++; }
    if (v0 == ks16(S1, 2)) { printf("FAIL ks16 ctr diff\n"); fails++; }
    if (v0 == ks16(0x5678, 0)) { printf("FAIL ks16 S diff\n"); fails++; }
}
    {
        uint8_t buf[64], orig[64];
        for (int i = 0; i < 64; i++) orig[i] = (uint8_t)i;
        memcpy(buf, orig, 64);
        stream_xor(buf, 64, 0x1234, 0);
        stream_xor(buf, 64, 0x1234, 0);
        if (memcmp(buf, orig, 64) != 0) { printf("FAIL stream_xor inv\n"); fails++; }
    }

    printf(fails ? "TESTS FAILED: %d\n" : "ALL TESTS OK\n", fails);
    return fails ? 1 : 0;
}

int main(int argc, char **argv) {
    const char *mode = NULL;
    const char *args[4] = {0};
    int nargs = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--debug") == 0) {
            g_debug = 1;
        } else if (!mode) {
            mode = argv[i];
        } else if (nargs < 4) {
            args[nargs++] = argv[i];
        }
    }

    if (self_test() != 0) return 1;

    if (mode && strcmp(mode, "test") == 0) return run_tests();
    if (mode && strcmp(mode, "keygen") == 0 && nargs >= 2)
        return keygen(args[0], args[1]);
    if (mode && strcmp(mode, "server") == 0 && nargs >= 2)
        return run_server(atoi(args[0]), args[1]);
    if (mode && strcmp(mode, "client") == 0 && nargs >= 3)
        return run_client(args[0], atoi(args[1]), args[2]);

    fprintf(stderr,
        "usage:\n"
        "  %s [-d] test\n"
        "  %s [-d] keygen <privfile> <pubfile>\n"
        "  %s [-d] server <port> <authorized_keys>\n"
        "  %s [-d] client <host> <port> <privfile>\n"
        "  -d, --debug  enable debug output\n",
        argv[0], argv[0], argv[0], argv[0]);
    return 1;
}
