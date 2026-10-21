#include "crypto/field.h"
#include "crypto/dh.h"
#include "crypto/kdf.h"
#include "crypto/cipher.h"
#include <stdio.h>
#include <time.h>
#include <string.h>

int main(void)
{
    const dh_ops_t *d;
    const kdf_ops_t *k;
    const cipher_ops_t *c;
    clock_t t0;
    int i;
    crypto_G = crypto_find_generator();
    printf("G=%u\n", crypto_G);
    for (d = crypto_dh_first(); d; d = crypto_dh_next(d)) {
        t0 = clock();
        for (i = 0; i < 1000; i++) {
            uint16_t A, n, p;
            d->client(&A, &n, &p);
        }
        printf("dh=%s %.1f us/op\n", d->name, (double)(clock() - t0) / CLOCKS_PER_SEC * 1e6 / 1000.0);
    }
    for (k = crypto_kdf_first(); k; k = crypto_kdf_next(k)) {
        t0 = clock();
        for (i = 0; i < 10000; i++) (void)k->ks16((uint16_t)i, 1234);
        printf("kdf=%s %.2f us/op\n", k->name, (double)(clock() - t0) / CLOCKS_PER_SEC * 1e6 / 10000.0);
    }
    for (c = crypto_cipher_first(); c; c = crypto_cipher_next(c)) {
        uint8_t buf[64];
        t0 = clock();
        for (i = 0; i < 10000; i++) c->xor(crypto_find_kdf("cube"), 1234, (uint16_t)i, buf, sizeof(buf));
        printf("cipher=%s %.2f us/op\n", c->name, (double)(clock() - t0) / CLOCKS_PER_SEC * 1e6 / 10000.0);
    }
    return 0;
}
