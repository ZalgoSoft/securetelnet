#include "crypto/dh.h"
#include "crypto/kdf.h"
#include "crypto/cipher.h"
#include "crypto/mac.h"
#include "crypto/prng.h"
#include "crypto/auth.h"
#include "compress.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    const char *names[64];
    int n = 0;
    const dh_ops_t *d;
    const kdf_ops_t *k;
    const cipher_ops_t *c;
    const mac_ops_t *m;
    const prng_ops_t *p;
    const auth_ops_t *a;
    const compress_ops_t *z;
    int i, j;
    names[n++] = "chat";
    names[n++] = "shell";
    names[n++] = "file";
    for (d = crypto_dh_first(); d; d = crypto_dh_next(d)) names[n++] = d->name;
    for (k = crypto_kdf_first(); k; k = crypto_kdf_next(k)) names[n++] = k->name;
    for (c = crypto_cipher_first(); c; c = crypto_cipher_next(c)) names[n++] = c->name;
    for (m = crypto_mac_first(); m; m = crypto_mac_next(m)) names[n++] = m->name;
    for (p = crypto_prng_first(); p; p = crypto_prng_next(p)) names[n++] = p->name;
    for (a = crypto_auth_first(); a; a = crypto_auth_next(a)) names[n++] = a->name;
    for (z = compress_first(); z; z = compress_next(z)) names[n++] = z->name;
    for (i = 0; i < n; i++)
        for (j = i + 1; j < n; j++)
            if (!strcmp(names[i], names[j])) {
                printf("duplicate: %s\n", names[i]);
                return 1;
            }
    printf("ok: %d unique names\n", n);
    return 0;
}
