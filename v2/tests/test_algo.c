#include "algo.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static uint32_t test_seed(void) {
    uint32_t s = (uint32_t)time(NULL) ^ ((uint32_t)getpid() << 16) ^ (uint32_t)clock();
    return s ? s : 1;
}

static int test_modpow(uint32_t sd) {
    printf("test modpow seed=%08x\n", sd);
    int fails = 0;
    uint16_t G = algo_g();
    printf("  G=%u P=%lu\n", G, P);
    if (modpow(G, 0) != 1) { printf("  FAIL exp0\n"); fails++; } else printf("  OK exp0\n");
    if (modpow(G, 1) != G) { printf("  FAIL exp1\n"); fails++; } else printf("  OK exp1\n");
    if (modpow(G, P - 1) != 1) { printf("  FAIL Fermat\n"); fails++; } else printf("  OK Fermat\n");
    return fails;
}

static int test_dh(uint32_t sd) {
    printf("test DH seed=%08x\n", sd);
    int fails = 0, bad = 0;
    uint16_t G = algo_g();
    for (int i = 0; i < 1000; i++) {
        uint16_t a = (uint16_t)(1 + (sd % (P - 2)));
        sd ^= sd << 13; sd ^= sd >> 17; sd ^= sd << 5;
        uint16_t b = (uint16_t)(1 + (sd % (P - 2)));
        sd ^= sd << 13; sd ^= sd >> 17; sd ^= sd << 5;
        uint16_t A = modpow(G, a), B = modpow(G, b);
        if (modpow(B, a) != modpow(A, b)) bad++;
    }
    printf("  pairs=1000 bad=%d seed_after=%08x\n", bad, sd);
    if (bad) fails++;
    return fails;
}

static int test_schnorr(uint32_t sd) {
    printf("test Schnorr seed=%08x\n", sd);
    int fails = 0;
    algo_config_t cfg; algo_config_default(&cfg);
    uint16_t G = algo_g();
    int bad = 0;
    for (int i = 0; i < 1000; i++) {
        uint16_t priv = (uint16_t)(1 + (sd % (P - 2)));
        sd ^= sd << 13; sd ^= sd >> 17; sd ^= sd << 5;
        uint16_t pub = modpow(G, priv);
        uint16_t c = (uint16_t)(sd & 0xFFFF);
        sd ^= sd << 13; sd ^= sd >> 17; sd ^= sd << 5;
        uint16_t R, s;
        schnorr_prove_cfg(priv, c, &R, &s, &sd, &cfg);
        if (!schnorr_verify_cfg(pub, c, R, s, &cfg)) bad++;
    }
    printf("  keys=1000 bad=%d seed_after=%08x\n", bad, sd);
    if (bad) fails++;

    int saved = 1;
    uint16_t priv = (uint16_t)(1 + (sd % (P - 2)));
    sd ^= sd << 13; sd ^= sd >> 17; sd ^= sd << 5;
    uint16_t pub = modpow(G, priv);
    uint16_t c = (uint16_t)(sd & 0xFFFF);
    sd ^= sd << 13; sd ^= sd >> 17; sd ^= sd << 5;
    uint16_t R, s;
    schnorr_prove_cfg(priv, c, &R, &s, &sd, &cfg);
    int accepted = 0;
    if (schnorr_verify_cfg(pub, (uint16_t)(c ^ 1), R, s, &cfg)) accepted++;
    if (schnorr_verify_cfg(pub, c, (uint16_t)(R ^ 1), s, &cfg)) accepted++;
    if (schnorr_verify_cfg(pub, c, R, (uint16_t)(s + 1), &cfg)) accepted++;
    if (schnorr_verify_cfg(modpow(G, priv + 1), c, R, s, &cfg)) accepted++;
    printf("  mutations=4 accepted=%d seed_after=%08x (saved=%d)\n", accepted, sd, saved);
    if (accepted) fails++;
    return fails;
}

static int test_ks16(uint32_t sd) {
    printf("test ks16 seed=%08x\n", sd);
    int fails = 0;
    uint16_t S1 = (uint16_t)(sd & 0xFFFF); sd ^= sd << 13; sd ^= sd >> 17; sd ^= sd << 5;
    uint16_t S2 = (uint16_t)(sd & 0xFFFF); sd ^= sd << 13; sd ^= sd >> 17; sd ^= sd << 5;
    uint16_t c1 = (uint16_t)(sd & 0xFFFF); sd ^= sd << 13; sd ^= sd >> 17; sd ^= sd << 5;
    uint16_t c2 = (uint16_t)(sd & 0xFFFF); sd ^= sd << 13; sd ^= sd >> 17; sd ^= sd << 5;
    if (S1 == S2) S2++;
    if (c1 == c2) c2++;
    printf("  S1=%04x S2=%04x c1=%04x c2=%04x\n", S1, S2, c1, c2);
    int ok = 1;
    if (ks16(S1, c1) != ks16(S1, c1)) { printf("  FAIL determ\n"); ok = 0; }
    if (ks16(S1, c1) == ks16(S2, c1)) { printf("  FAIL S diff\n"); ok = 0; }
    if (ks16(S1, c1) == ks16(S1, c2)) { printf("  FAIL ctr diff\n"); ok = 0; }
    if (ok) printf("  OK determ/diff\n"); else fails++;

    uint32_t pairs = 4096;
    int coll = 0;
    for (uint32_t i = 0; i < pairs; i++) {
        uint16_t Sx = (uint16_t)(sd & 0xFFFF); sd ^= sd << 13; sd ^= sd >> 17; sd ^= sd << 5;
        uint16_t ca = (uint16_t)(sd & 0xFFFF); sd ^= sd << 13; sd ^= sd >> 17; sd ^= sd << 5;
        uint16_t cb = (uint16_t)(sd & 0xFFFF); sd ^= sd << 13; sd ^= sd >> 17; sd ^= sd << 5;
        if (ca != cb && ks16(Sx, ca) == ks16(Sx, cb)) coll++;
    }
    double p = (double)pairs / 65536.0;
    printf("  collision pairs=%u observed=%d expected~%.3f seed_after=%08x\n",
           pairs, coll, p, sd);
    return fails;
}

static int test_stream_xor(uint32_t sd) {
    printf("test stream_xor seed=%08x\n", sd);
    int fails = 0;
    algo_config_t variants[] = {
        {DH_NORMAL, AUTH_SCHNORR, 0, KDF_CUBE, CIPHER_KS16, MAC_KS16, PRNG_XORSHIFT, COMPRESS_NONE},
        {DH_NORMAL, AUTH_SCHNORR, 0, KDF_CUBE, CIPHER_RAW, MAC_KS16, PRNG_XORSHIFT, COMPRESS_NONE},
        {DH_NORMAL, AUTH_SCHNORR, 0, KDF_CUBE, CIPHER_BLOCK, MAC_KS16, PRNG_XORSHIFT, COMPRESS_NONE},
        {DH_NORMAL, AUTH_SCHNORR, 0, KDF_BYTE, CIPHER_KS16, MAC_KS16, PRNG_XORSHIFT, COMPRESS_NONE},
        {DH_NORMAL, AUTH_SCHNORR, 0, KDF_DOUBLE, CIPHER_KS16, MAC_KS16, PRNG_XORSHIFT, COMPRESS_NONE},
    };
    const char *names[] = {"ks16", "raw", "block", "kdf_byte", "kdf_double"};
    for (int v = 0; v < 5; v++) {
        uint16_t S1 = (uint16_t)(sd & 0xFFFF); sd ^= sd << 13; sd ^= sd >> 17; sd ^= sd << 5;
        uint16_t c1 = (uint16_t)(sd & 0xFFFF); sd ^= sd << 13; sd ^= sd >> 17; sd ^= sd << 5;
        uint8_t buf[64], orig[64];
        for (int i = 0; i < 64; i++) orig[i] = (uint8_t)(sd & 0xFF);
        memcpy(buf, orig, 64);
        stream_xor_cfg(buf, 64, S1, c1, &variants[v]);
        stream_xor_cfg(buf, 64, S1, c1, &variants[v]);
        int ok = (memcmp(buf, orig, 64) == 0);
        printf("  %-10s S=%04x ctr=%04x len=64 ok=%d\n", names[v], S1, c1, ok);
        if (!ok) fails++;
    }
    printf("  seed_after=%08x\n", sd);
    return fails;
}

static int test_prng(uint32_t sd) {
    printf("test prng seed=%08x\n", sd);
    int fails = 0;
    algo_config_t cfg; algo_config_default(&cfg);
    uint32_t s1 = sd, s2 = sd;
    cfg.prng_mode = PRNG_XORSHIFT;
    uint32_t v1 = prng_next(&s1, &cfg);
    cfg.prng_mode = PRNG_MASK;
    uint32_t v2 = prng_next(&s2, &cfg);
    printf("  xorshift=%08x mask=%08x mask<=0xffff=%d\n", v1, v2, v2 <= 0xFFFF);
    if (v2 > 0xFFFF) fails++;
    return fails;
}

static int test_auth_hmac(uint32_t sd) {
    printf("test auth_hmac seed=%08x\n", sd);
    int fails = 0;
    algo_config_t cfg; algo_config_default(&cfg);
    cfg.auth_mode = AUTH_HMAC;
    uint16_t keys[3];
    for (int i = 0; i < 3; i++) {
        keys[i] = (uint16_t)(sd & 0xFFFF);
        sd ^= sd << 13; sd ^= sd >> 17; sd ^= sd << 5;
    }
    uint16_t S = (uint16_t)(sd & 0xFFFF);
    sd ^= sd << 13; sd ^= sd >> 17; sd ^= sd << 5;
    uint16_t priv = keys[1];
    uint16_t c = 0x1234;
    uint16_t tag = ks16_cfg(S, (uint16_t)(priv ^ c), cfg.kdf_mode);
    printf("  S=%04x priv=%04x c=%04x tag=%04x\n", S, priv, c, tag);
    int ok = 0;
    for (int i = 0; i < 3; i++) {
        uint16_t expect = ks16_cfg(S, (uint16_t)(keys[i] ^ c), cfg.kdf_mode);
        if (expect == tag) { ok = 1; printf("  match key[%d]=%04x\n", i, keys[i]); break; }
    }
    if (!ok) { printf("  FAIL no match\n"); fails++; }
    else printf("  OK\n");
    return fails;
}

int main(void) {
    if (algo_self_test() != 0) { fprintf(stderr, "self-test failed\n"); return 1; }
    uint32_t sd = test_seed();
    printf("tests: seed=%08x G=%u\n", sd, algo_g());
    int fails = 0;
    fails += test_modpow(sd);
    fails += test_dh(sd);
    fails += test_schnorr(sd);
    fails += test_ks16(sd);
    fails += test_stream_xor(sd);
    fails += test_prng(sd);
    fails += test_auth_hmac(sd);
    printf(fails ? "TESTS FAILED: %d\n" : "ALL TESTS OK\n", fails);
    return fails ? 1 : 0;
}
