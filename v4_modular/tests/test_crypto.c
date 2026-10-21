#include "crypto/context.h"
#include "crypto/field.h"
#include "crypto/dh.h"
#include "crypto/kdf.h"
#include "crypto/cipher.h"
#include "crypto/mac.h"
#include "crypto/prng.h"
#include "crypto/auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int failures = 0;

static void expect(int cond, const char *msg)
{
    if (!cond) { printf("FAIL: %s\n", msg); failures++; }
}

int main(void)
{
    unsigned seed = (unsigned)time(0) ^ (unsigned)getpid() ^ (unsigned)clock();
    int i;
    printf("seed=%u\n", seed);
    srand(seed);
    crypto_G = crypto_find_generator();
    expect(crypto_G != 0, "generator found");
    printf("G=%u\n", crypto_G);

    for (i = 2; i < 100; i++) {
        uint16_t b = (uint16_t)(crypto_modpow((uint16_t)i, 1, crypto_P));
        expect(b == (uint16_t)(i % crypto_P), "modpow exp 1");
        expect(crypto_modpow((uint16_t)i, 0, crypto_P) == 1, "modpow exp 0");
    }

    for (i = 0; i < 1000; i++) {
        uint16_t a = (uint16_t)(1 + rand() % (crypto_P - 2));
        uint16_t b = (uint16_t)(1 + rand() % (crypto_P - 2));
        uint16_t A = crypto_modpow(crypto_G, a, crypto_P);
        uint16_t B = crypto_modpow(crypto_G, b, crypto_P);
        uint16_t s1 = crypto_modpow(B, a, crypto_P);
        uint16_t s2 = crypto_modpow(A, b, crypto_P);
        expect(s1 == s2, "DH symmetry");
    }

    {
        const auth_ops_t *au = crypto_find_auth("schnorr");
        uint16_t S = 1234, priv = 42, c;
        uint16_t pub = crypto_modpow(crypto_G, priv, crypto_P);
        uint16_t R, sv;
        au->server(0, S, 0, &c);
        crypto_auth_schnorr_prove(S, priv, c, &R, &sv);
        expect(crypto_auth_schnorr_verify(S, pub, c, R, sv) == 0, "schnorr verify");
        expect(crypto_auth_schnorr_verify(S, pub, c, R, (uint16_t)(sv + 1)) != 0, "schnorr soundness");
    }

    {
        const auth_ops_t *au = crypto_find_auth("hmac");
        const kdf_ops_t *kd = crypto_find_kdf("cube");
        uint16_t S = 777, priv = 99, c;
        uint16_t tag_client, tag_server;
        au->server(kd, S, 0, &c);
        au->client(kd, S, priv, c, &tag_client, 0);
        tag_server = kd->ks16(S, (uint16_t)(priv ^ c));
        expect(tag_client == tag_server, "hmac auth");
    }

    {
        const kdf_ops_t *kd = crypto_find_kdf("cube");
        uint16_t a = kd->ks16(1234, 5678);
        uint16_t b = kd->ks16(1234, 5678);
        expect(a == b, "kdf determinism");
        expect(kd->ks16(1234, 5679) != a, "kdf difference");
    }

    {
        const cipher_ops_t *ci;
        const kdf_ops_t *kd = crypto_find_kdf("cube");
        uint8_t buf[16];
        for (ci = crypto_cipher_first(); ci; ci = crypto_cipher_next(ci)) {
            memset(buf, 0xAB, sizeof(buf));
            ci->xor(kd, 5000, 10, buf, sizeof(buf));
            ci->xor(kd, 5000, 10, buf, sizeof(buf));
            expect(buf[0] == 0xAB && buf[15] == 0xAB, "cipher involution");
        }
    }

    {
        const prng_ops_t *pr = crypto_find_prng("mask");
        uint32_t st = 0x12345678;
        for (i = 0; i < 100; i++) {
            uint16_t v = pr->next(&st);
            expect((v & 0x8000) == 0, "prng mask");
        }
    }

    printf("failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
