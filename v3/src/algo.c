#include "algo.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static uint16_t g_G = 0;

void algo_config_default(algo_config_t *cfg) {
    cfg->dh_mode = DH_NORMAL;
    cfg->auth_mode = AUTH_SCHNORR;
    cfg->schnorr_cache = 0;
    cfg->kdf_mode = KDF_CUBE;
    cfg->cipher_mode = CIPHER_KS16;
    cfg->mac_mode = MAC_KS16;
    cfg->prng_mode = PRNG_XORSHIFT;
    cfg->compress_mode = COMPRESS_NONE;
}

int algo_parse_dh(const char *s) {
    if (!strcmp(s, "normal")) return DH_NORMAL;
    if (!strcmp(s, "test"))   return DH_TEST;
    return -1;
}

int algo_parse_auth(const char *s) {
    if (!strcmp(s, "schnorr")) return AUTH_SCHNORR;
    if (!strcmp(s, "hmac"))    return AUTH_HMAC;
    return -1;
}

int algo_parse_schnorr(const char *s) {
    if (!strcmp(s, "plain")) return 0;
    if (!strcmp(s, "cache")) return 1;
    return -1;
}

int algo_parse_kdf(const char *s) {
    if (!strcmp(s, "cube"))   return KDF_CUBE;
    if (!strcmp(s, "byte"))   return KDF_BYTE;
    if (!strcmp(s, "double")) return KDF_DOUBLE;
    return -1;
}

int algo_parse_cipher(const char *s) {
    if (!strcmp(s, "ks16"))  return CIPHER_KS16;
    if (!strcmp(s, "raw"))   return CIPHER_RAW;
    if (!strcmp(s, "block")) return CIPHER_BLOCK;
    return -1;
}

int algo_parse_mac(const char *s) {
    if (!strcmp(s, "ks16"))    return MAC_KS16;
    if (!strcmp(s, "precalc")) return MAC_PRECALC;
    return -1;
}

int algo_parse_prng(const char *s) {
    if (!strcmp(s, "xorshift")) return PRNG_XORSHIFT;
    if (!strcmp(s, "mask"))     return PRNG_MASK;
    if (!strcmp(s, "clock"))    return PRNG_CLOCK;
    return -1;
}

int algo_parse_compress(const char *s) {
    if (!strcmp(s, "none")) return COMPRESS_NONE;
    if (!strcmp(s, "rle"))  return COMPRESS_RLE;
    if (!strcmp(s, "lz4"))  return COMPRESS_LZ4;
    return -1;
}

uint16_t modpow(uint16_t base, uint32_t exp) {
    uint32_t result = 1;
    uint32_t b = base % P;
    while (exp) {
        if (exp & 1) result = (result * b) % P;
        b = (b * b) % P;
        exp >>= 1;
    }
    return (uint16_t)result;
}

uint32_t prng_next(uint32_t *state, const algo_config_t *cfg) {
    if (cfg && cfg->prng_mode == PRNG_CLOCK) {
        *state ^= (uint32_t)clock();
    }
    uint32_t x = *state;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    *state = x;
    if (cfg && cfg->prng_mode == PRNG_MASK) return x & 0xFFFF;
    return x;
}

uint16_t ks16(uint16_t S, uint16_t ctr) {
    uint32_t x = ((uint32_t)S ^ ctr) | 1;
    x %= P;
    uint32_t x2 = (x * x) % P;
    return (uint16_t)((x2 * x) % P);
}

uint16_t ks16_cfg(uint16_t S, uint16_t ctr, int kdf_mode) {
    if (kdf_mode == KDF_BYTE) return (uint16_t)((S ^ ctr) & 0xFF);
    uint16_t v = ks16(S, ctr);
    if (kdf_mode == KDF_DOUBLE) v = ks16(v, (uint16_t)(ctr ^ 0xAAAA));
    return v;
}

uint8_t ks_byte_cfg(uint16_t S, uint16_t ctr, uint8_t i, const algo_config_t *cfg) {
    uint16_t v = ks16_cfg(S, (uint16_t)(ctr + i), cfg->kdf_mode);
    return (uint8_t)(v ^ (v >> 8));
}

void stream_xor_cfg(uint8_t *buf, size_t n, uint16_t S, uint16_t ctr,
                    const algo_config_t *cfg) {
    if (cfg->cipher_mode == CIPHER_BLOCK) {
        for (size_t i = 0; i < n; i += 2) {
            uint16_t v = ks16_cfg(S, (uint16_t)(ctr + i / 2), cfg->kdf_mode);
            buf[i] ^= (uint8_t)(v & 0xFF);
            if (i + 1 < n) buf[i + 1] ^= (uint8_t)(v >> 8);
        }
        return;
    }
    for (size_t i = 0; i < n; i++) {
        uint8_t k;
        if (cfg->cipher_mode == CIPHER_RAW)
            k = (uint8_t)(ks16_cfg(S, (uint16_t)(ctr + i), cfg->kdf_mode) & 0xFF);
        else
            k = ks_byte_cfg(S, ctr, (uint8_t)i, cfg);
        buf[i] ^= k;
    }
}

static uint16_t g_cache_pub = 0;
static uint16_t g_cache_arr[256];
static int g_cache_valid = 0;

void schnorr_prove(uint16_t priv, uint16_t c, uint16_t *R, uint16_t *s,
                   uint32_t *seed) {
    algo_config_t def;
    algo_config_default(&def);
    schnorr_prove_cfg(priv, c, R, s, seed, &def);
}

int schnorr_verify(uint16_t pub, uint16_t c, uint16_t R, uint16_t s) {
    algo_config_t def;
    algo_config_default(&def);
    return schnorr_verify_cfg(pub, c, R, s, &def);
}

void schnorr_prove_cfg(uint16_t priv, uint16_t c, uint16_t *R, uint16_t *s,
                       uint32_t *seed, const algo_config_t *cfg) {
    uint16_t r = (uint16_t)(1 + (prng_next(seed, cfg) % (P - 2)));
    *R = modpow(g_G, r);
    uint32_t cs = ((uint32_t)c * priv) % (P - 1);
    *s = (uint16_t)(((uint32_t)r + cs) % (P - 1));
}

int schnorr_verify_cfg(uint16_t pub, uint16_t c, uint16_t R, uint16_t s,
                       const algo_config_t *cfg) {
    uint16_t lhs = modpow(g_G, s);
    uint16_t pc;
    if (cfg && cfg->schnorr_cache) {
        if (!g_cache_valid || g_cache_pub != pub) {
            for (int i = 0; i < 256; i++)
                g_cache_arr[i] = modpow(pub, (uint16_t)i);
            g_cache_pub = pub; g_cache_valid = 1;
        }
        if (c < 256) pc = g_cache_arr[c];
        else pc = modpow(pub, c);
    } else {
        pc = modpow(pub, c);
    }
    uint16_t rhs = (uint16_t)(((uint32_t)R * pc) % P);
    return lhs == rhs;
}

uint16_t mac_cfg(uint16_t S, uint16_t ctr, const algo_config_t *cfg) {
    if (cfg->mac_mode == MAC_PRECALC) return ks16_cfg(S, (uint16_t)(ctr ^ 0xFFFF), cfg->kdf_mode);
    return ks16_cfg(S, (uint16_t)(ctr ^ 0xFFFF), cfg->kdf_mode);
}

static void fill_nonce(uint8_t *buf, size_t n, uint32_t *seed, const algo_config_t *cfg) {
    for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)(prng_next(seed, cfg) >> 24);
}

int read_full(int fd, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (uint8_t*)buf + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

int write_full(int fd, const void *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, (const uint8_t*)buf + sent, n - sent);
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

int dh_client_cfg(int fd, uint16_t *S, uint32_t *ctr, uint32_t *seed,
                  const algo_config_t *cfg) {
    uint16_t a;
    uint16_t A;
    if (cfg->dh_mode == DH_TEST) {
        a = (uint16_t)((prng_next(seed, cfg) & 0xFF) + 1);
        A = modpow(g_G, a);
    } else {
        a = (uint16_t)(1 + (prng_next(seed, cfg) % (P - 2)));
        A = modpow(g_G, a);
    }
    uint8_t nonce[NONCE_LEN]; fill_nonce(nonce, NONCE_LEN, seed, cfg);
    uint8_t pkt[2 + NONCE_LEN];
    pkt[0] = A & 0xFF; pkt[1] = A >> 8;
    memcpy(pkt + 2, nonce, NONCE_LEN);
    if (write_full(fd, pkt, sizeof(pkt)) < 0) return -1;

    uint8_t resp[2 + NONCE_LEN];
    if (read_full(fd, resp, sizeof(resp)) < 0) return -1;
    uint16_t B = (uint16_t)(resp[0] | (resp[1] << 8));
    if (B == 0 || B == 1 || B == (uint16_t)(P - 1) || B >= P) return -1;
    uint32_t peer_nonce = 0;
    for (int i = 0; i < NONCE_LEN; i++) peer_nonce = (peer_nonce << 8) | resp[2 + i];
    *S = modpow(B, a);
    *ctr = peer_nonce;
    return 0;
}

int dh_server_cfg(int fd, uint16_t *S, uint32_t *ctr, uint32_t *seed,
                  const algo_config_t *cfg) {
    uint8_t pkt[2 + NONCE_LEN];
    if (read_full(fd, pkt, sizeof(pkt)) < 0) return -1;
    uint16_t A = (uint16_t)(pkt[0] | (pkt[1] << 8));
    if (A == 0 || A == 1 || A == (uint16_t)(P - 1) || A >= P) return -1;

    uint16_t b;
    if (cfg->dh_mode == DH_TEST) b = (uint16_t)((prng_next(seed, cfg) & 0xFF) + 1);
    else b = (uint16_t)(1 + (prng_next(seed, cfg) % (P - 2)));
    uint16_t B = modpow(g_G, b);
    uint8_t nonce[NONCE_LEN]; fill_nonce(nonce, NONCE_LEN, seed, cfg);

    uint8_t resp[2 + NONCE_LEN];
    resp[0] = B & 0xFF; resp[1] = B >> 8;
    memcpy(resp + 2, nonce, NONCE_LEN);
    if (write_full(fd, resp, sizeof(resp)) < 0) return -1;

    uint32_t peer_nonce = 0;
    for (int i = 0; i < NONCE_LEN; i++) peer_nonce = (peer_nonce << 8) | pkt[2 + i];
    *S = modpow(A, b);
    *ctr = peer_nonce;
    return 0;
}

int auth_schnorr_server(int fd, const uint16_t *keys, int nkeys,
                        uint16_t S, uint32_t *seed, const algo_config_t *cfg) {
    uint16_t rnd = (uint16_t)(prng_next(seed, cfg) & 0xFFFF);
    uint16_t c = (uint16_t)(ks16_cfg(S, rnd, cfg->kdf_mode) ^ 0xFFFF);
    if (c == 0) c = 1;
    uint8_t pkt[2] = { c & 0xFF, c >> 8 };
    if (write_full(fd, pkt, 2) < 0) return -1;
    uint8_t resp[4];
    if (read_full(fd, resp, 4) < 0) return -1;
    uint16_t R = (uint16_t)(resp[0] | (resp[1] << 8));
    uint16_t s = (uint16_t)(resp[2] | (resp[3] << 8));
    if (R == 0) {
        uint8_t nok[2] = {'N','K'};
        write_full(fd, nok, 2);
        return -1;
    }
    int ok = 0;
    for (int i = 0; i < nkeys && !ok; i++)
        if (schnorr_verify_cfg(keys[i], c, R, s, cfg)) ok = 1;
    uint8_t r[2] = { ok ? 'O' : 'N', 'K' };
    if (write_full(fd, r, 2) < 0) return -1;
    return ok ? 0 : -1;
}

int auth_schnorr_client(int fd, uint16_t priv, uint32_t *seed,
                        const algo_config_t *cfg) {
    uint8_t pkt[2];
    if (read_full(fd, pkt, 2) < 0) return -1;
    uint16_t c = (uint16_t)(pkt[0] | (pkt[1] << 8));
    uint16_t R, s;
    schnorr_prove_cfg(priv, c, &R, &s, seed, cfg);
    uint8_t resp[4] = { R & 0xFF, R >> 8, s & 0xFF, s >> 8 };
    if (write_full(fd, resp, 4) < 0) return -1;
    uint8_t ok[2];
    if (read_full(fd, ok, 2) < 0) return -1;
    return (ok[0] == 'O' && ok[1] == 'K') ? 0 : -1;
}

int auth_hmac_server(int fd, const uint16_t *keys, int nkeys,
                     uint16_t S, uint32_t *seed, const algo_config_t *cfg) {
    uint16_t c = (uint16_t)(prng_next(seed, cfg) & 0xFFFF);
    uint8_t pkt[2] = { c & 0xFF, c >> 8 };
    if (write_full(fd, pkt, 2) < 0) return -1;
    uint8_t resp[2];
    if (read_full(fd, resp, 2) < 0) return -1;
    uint16_t tag = (uint16_t)(resp[0] | (resp[1] << 8));
    int ok = 0;
    for (int i = 0; i < nkeys && !ok; i++) {
        uint16_t expect = ks16_cfg(S, (uint16_t)(keys[i] ^ c), cfg->kdf_mode);
        if (expect == tag) ok = 1;
    }
    uint8_t r[2] = { ok ? 'O' : 'N', 'K' };
    if (write_full(fd, r, 2) < 0) return -1;
    return ok ? 0 : -1;
}

int auth_hmac_client(int fd, uint16_t priv, uint16_t S,
                     const algo_config_t *cfg) {
    uint8_t pkt[2];
    if (read_full(fd, pkt, 2) < 0) return -1;
    uint16_t c = (uint16_t)(pkt[0] | (pkt[1] << 8));
    uint16_t tag = ks16_cfg(S, (uint16_t)(priv ^ c), cfg->kdf_mode);
    uint8_t resp[2] = { tag & 0xFF, tag >> 8 };
    if (write_full(fd, resp, 2) < 0) return -1;
    uint8_t ok[2];
    if (read_full(fd, ok, 2) < 0) return -1;
    return (ok[0] == 'O' && ok[1] == 'K') ? 0 : -1;
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

uint16_t algo_g(void) { return g_G; }

int algo_self_test(void) {
    if ((P - 1) % 3 == 0) { fprintf(stderr, "self-test: p-1 div by 3\n"); return 1; }
    if ((3UL * D_INV) % (P - 1) != 1) { fprintf(stderr, "self-test: D_INV\n"); return 1; }
    g_G = find_generator();
    if (g_G == 0) { fprintf(stderr, "self-test: no generator\n"); return 1; }
    for (uint16_t x = 1; x < 100; x++) {
        uint16_t y = (uint16_t)(((uint32_t)x * x % P) * x % P);
        if (modpow(y, D_INV) != x) { fprintf(stderr, "self-test: cube inv %u\n", x); return 1; }
    }
    return 0;
}
