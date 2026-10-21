#ifndef CRYPTO_KDF_H
#define CRYPTO_KDF_H

#include <stdint.h>

typedef struct kdf_ops {
    const char *name;
    uint16_t (*ks16)(uint16_t S, uint16_t ctr);
    uint8_t (*byte)(uint16_t S, uint16_t ctr);
} kdf_ops_t;

extern const kdf_ops_t kdf_cube_ops;
extern const kdf_ops_t kdf_byte_ops;
extern const kdf_ops_t kdf_double_ops;

const kdf_ops_t *crypto_find_kdf(const char *name);
const kdf_ops_t *crypto_kdf_first(void);
const kdf_ops_t *crypto_kdf_next(const kdf_ops_t *cur);

#endif
