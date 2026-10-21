#include "crypto/cipher.h"
#include <string.h>

static const cipher_ops_t *cipher_list[] = {
    &cipher_ks16_ops,
    &cipher_raw_ops,
    &cipher_block_ops
};

#define CIPHER_COUNT (sizeof(cipher_list)/sizeof(cipher_list[0]))

const cipher_ops_t *crypto_find_cipher(const char *name)
{
    size_t i;
    for (i = 0; i < CIPHER_COUNT; i++) {
        if (strcmp(cipher_list[i]->name, name) == 0)
            return cipher_list[i];
    }
    return 0;
}

const cipher_ops_t *crypto_cipher_first(void) { return cipher_list[0]; }

const cipher_ops_t *crypto_cipher_next(const cipher_ops_t *cur)
{
    size_t i;
    for (i = 0; i < CIPHER_COUNT; i++) {
        if (cipher_list[i] == cur && i + 1 < CIPHER_COUNT)
            return cipher_list[i + 1];
    }
    return 0;
}
