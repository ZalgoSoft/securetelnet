#ifndef CRYPTO_CIPHER_H
#define CRYPTO_CIPHER_H

#include <stdint.h>
#include <stddef.h>
#include "kdf.h"

typedef struct cipher_ops {
    const char *name;
    void (*xor)(const kdf_ops_t *kdf, uint16_t S, uint16_t ctr, uint8_t *buf, size_t len);
} cipher_ops_t;

extern const cipher_ops_t cipher_ks16_ops;
extern const cipher_ops_t cipher_raw_ops;
extern const cipher_ops_t cipher_block_ops;

const cipher_ops_t *crypto_find_cipher(const char *name);
const cipher_ops_t *crypto_cipher_first(void);
const cipher_ops_t *crypto_cipher_next(const cipher_ops_t *cur);

#endif
