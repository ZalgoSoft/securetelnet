#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define P 65519UL
#define D_INV 43679UL
#define MAX_KEYS 16

static uint16_t G = 0;

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

static void schnorr_prove(uint16_t priv, uint16_t c,
                          uint16_t *R_out, uint16_t *s_out,
                          uint32_t *seed) {
    uint16_t r = (uint16_t)(1 + (xorshift32(seed) % (P - 2)));
    uint16_t R = modpow(G, r);
    uint32_t cs = ((uint32_t)c * priv) % (P - 1);
    uint16_t s = (uint16_t)(((uint32_t)r + cs) % (P - 1));
    *R_out = R;
    *s_out = s;
}

static int schnorr_verify(uint16_t pub, uint16_t c, uint16_t R, uint16_t s) {
    uint16_t lhs = modpow(G, s);
    uint16_t rhs = (uint16_t)(((uint32_t)R * modpow(pub, c)) % P);
    return lhs == rhs;
}

static int handshake_client(int fd, uint16_t *S_out, uint32_t *ctr_out, uint32_t *seed) {
    uint16_t a = (uint16_t)(1 + (xorshift32(seed) % (P - 2)));
    uint16_t A = modpow(G, a);
    uint8_t nonce[8]; fill_random(nonce, 8, seed);

    uint8_t pkt[10];
    pkt[0] = A & 0xFF; pkt[1] = A >> 8;
    memcpy(pkt + 2, nonce, 8);
    if (write_full(fd, pkt, 10) < 0) return -1;

    uint8_t resp[10];
    if (read_full(fd, resp, 10) < 0) return -1;
    uint16_t B = (uint16_t)(resp[0] | (resp[1] << 8));
    uint32_t peer_nonce = 0;
    for (int i = 0; i < 4; i++) peer_nonce = (peer_nonce << 8) | resp[2 + i];

    if (B == 0 || B >= P) return -1;
    *S_out = modpow(B, a);
    *ctr_out = peer_nonce;
    return 0;
}

static int handshake_server(int fd, uint16_t *S_out, uint32_t *ctr_out, uint32_t *seed) {
    uint8_t pkt[10];
    if (read_full(fd, pkt, 10) < 0) return -1;
    uint16_t A = (uint16_t)(pkt[0] | (pkt[1] << 8));
    if (A == 0 || A >= P) return -1;

    uint16_t b = (uint16_t)(1 + (xorshift32(seed) % (P - 2)));
    uint16_t B = modpow(G, b);
    uint8_t nonce[8]; fill_random(nonce, 8, seed);

    uint8_t resp[10];
    resp[0] = B & 0xFF; resp[1] = B >> 8;
    memcpy(resp + 2, nonce, 8);
    if (write_full(fd, resp, 10) < 0) return -1;

    uint32_t peer_nonce = 0;
    for (int i = 0; i < 4; i++) peer_nonce = (peer_nonce << 8) | pkt[2 + i];

    *S_out = modpow(A, b);
    *ctr_out = peer_nonce;
    return 0;
}

static int auth_server_key(int fd, uint16_t pub, uint16_t S, uint32_t *seed) {
    uint16_t rnd = (uint16_t)(xorshift32(seed) & 0xFFFF);
    uint16_t c = (uint16_t)(ks16(S, rnd) ^ 0xFFFF);
    uint8_t pkt[2] = { c & 0xFF, c >> 8 };
    if (write_full(fd, pkt, 2) < 0) return -1;

    uint8_t resp[4];
    if (read_full(fd, resp, 4) < 0) return -1;
    uint16_t R = (uint16_t)(resp[0] | (resp[1] << 8));
    uint16_t s = (uint16_t)(resp[2] | (resp[3] << 8));

    if (!schnorr_verify(pub, c, R, s)) {
        uint8_t nok[2] = {'N','K'};
        write_full(fd, nok, 2);
        return -1;
    }
    uint8_t ok[2] = {'O','K'};
    write_full(fd, ok, 2);
    return 0;
}

static int auth_client_key(int fd, uint16_t priv, uint32_t *seed) {
    uint8_t pkt[2];
    if (read_full(fd, pkt, 2) < 0) return -1;
    uint16_t c = (uint16_t)(pkt[0] | (pkt[1] << 8));

    uint16_t R, s;
    schnorr_prove(priv, c, &R, &s, seed);

    uint8_t resp[4] = { R & 0xFF, R >> 8, s & 0xFF, s >> 8 };
    if (write_full(fd, resp, 4) < 0) return -1;

    uint8_t ok[2];
    if (read_full(fd, ok, 2) < 0) return -1;
    return (ok[0] == 'O' && ok[1] == 'K') ? 0 : -1;
}

static int send_packet(int fd, const uint8_t *data, uint16_t len, uint16_t S, uint16_t *ctr) {
    uint8_t pkt[4 + 65535 + 2];
    uint16_t c = *ctr;
    pkt[0] = c & 0xFF; pkt[1] = c >> 8;
    pkt[2] = len & 0xFF; pkt[3] = len >> 8;
    memcpy(pkt + 4, data, len);
    stream_xor(pkt + 4, len, S, c);
    uint16_t tag = ks16(S, (uint16_t)(c ^ 0xFFFF));
    pkt[4 + len] = tag & 0xFF;
    pkt[4 + len + 1] = tag >> 8;
    if (write_full(fd, pkt, 4 + len + 2) < 0) return -1;
    *ctr = c + 1;
    return 0;
}

static int recv_packet(int fd, uint8_t *out, uint16_t *out_len, uint16_t S, uint16_t *ctr) {
    uint8_t hdr[4];
    if (read_full(fd, hdr, 4) < 0) return -1;
    uint16_t c = (uint16_t)(hdr[0] | (hdr[1] << 8));
    uint16_t len = (uint16_t)(hdr[2] | (hdr[3] << 8));
    if (read_full(fd, out, len + 2) < 0) return -1;
    uint16_t tag = (uint16_t)(out[len] | (out[len + 1] << 8));
    uint16_t expect = ks16(S, (uint16_t)(c ^ 0xFFFF));
    if (tag != expect) { fprintf(stderr, "MAC mismatch!\n"); return -1; }
    stream_xor(out, len, S, c);
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
    return n;
}

static int keygen(const char *privpath, const char *pubpath) {
    uint32_t seed = (uint32_t)time(NULL) ^ (uint32_t)getpid();
    uint16_t priv = (uint16_t)(1 + (xorshift32(&seed) % (P - 2)));
    uint16_t pub  = modpow(G, priv);
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
    uint16_t S; uint32_t ctr32;
    if (handshake_server(cfd, &S, &ctr32, &seed) < 0) { fprintf(stderr, "handshake failed\n"); return 1; }
    uint16_t ctr = (uint16_t)ctr32;

    int ok = 0;
    for (int i = 0; i < nkeys && !ok; i++) {
        if (auth_server_key(cfd, keys[i], S, &seed) == 0) ok = 1;
    }
    if (!ok) { fprintf(stderr, "auth failed\n"); close(cfd); close(sfd); return 1; }
    printf("server: auth OK, S=%u\n", S);

    char line[512];
    while (fgets(line, sizeof(line), stdin)) {
        size_t n = strlen(line);
        if (n && line[n-1] == '\n') line[--n] = 0;
        if (send_packet(cfd, (uint8_t*)line, (uint16_t)n, S, &ctr) < 0) break;
        uint8_t in[1024]; uint16_t inlen;
        if (recv_packet(cfd, in, &inlen, S, &ctr) < 0) break;
        in[inlen] = 0;
        printf("client> %s\n", in);
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

    uint32_t seed = (uint32_t)time(NULL) ^ (uint32_t)getpid() ^ 0xA5A5A5A5u;
    uint16_t S; uint32_t ctr32;
    if (handshake_client(fd, &S, &ctr32, &seed) < 0) { fprintf(stderr, "handshake failed\n"); return 1; }
    uint16_t ctr = (uint16_t)ctr32;

    if (auth_client_key(fd, priv, &seed) < 0) {
        fprintf(stderr, "auth failed\n");
        close(fd);
        return 1;
    }
    printf("client: auth OK, S=%u\n", S);

    char line[512];
    while (fgets(line, sizeof(line), stdin)) {
        size_t n = strlen(line);
        if (n && line[n-1] == '\n') line[--n] = 0;
        if (send_packet(fd, (uint8_t*)line, (uint16_t)n, S, &ctr) < 0) break;
        uint8_t in[1024]; uint16_t inlen;
        if (recv_packet(fd, in, &inlen, S, &ctr) < 0) break;
        in[inlen] = 0;
        printf("server> %s\n", in);
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

int main(int argc, char **argv) {
    if (self_test() != 0) return 1;
    if (argc >= 4 && strcmp(argv[1], "keygen") == 0)
        return keygen(argv[2], argv[3]);
    if (argc >= 4 && strcmp(argv[1], "server") == 0)
        return run_server(atoi(argv[2]), argv[3]);
    if (argc >= 5 && strcmp(argv[1], "client") == 0)
        return run_client(argv[2], atoi(argv[3]), argv[4]);
    fprintf(stderr,
        "usage:\n"
        "  %s keygen <privfile> <pubfile>\n"
        "  %s server <port> <authorized_keys>\n"
        "  %s client <host> <port> <privfile>\n", argv[0], argv[0], argv[0]);
    return 1;
}
