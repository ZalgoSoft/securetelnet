#ifndef CRYPTO_PRNG_H
#define CRYPTO_PRNG_H

#include <stdint.h>

typedef struct prng_ops {
    const char *name;
    uint16_t (*next)(uint32_t *state);
} prng_ops_t;

extern const prng_ops_t prng_xorshift_ops;
extern const prng_ops_t prng_mask_ops;
extern const prng_ops_t prng_clock_ops;

const prng_ops_t *crypto_find_prng(const char *name);
const prng_ops_t *crypto_prng_first(void);
const prng_ops_t *crypto_prng_next(const prng_ops_t *cur);

#endif
