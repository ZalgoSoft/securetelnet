#include "crypto/prng.h"
#include <string.h>

static const prng_ops_t *prng_list[] = {
    &prng_xorshift_ops,
    &prng_mask_ops,
    &prng_clock_ops
};

#define PRNG_COUNT (sizeof(prng_list)/sizeof(prng_list[0]))

const prng_ops_t *crypto_find_prng(const char *name)
{
    size_t i;
    for (i = 0; i < PRNG_COUNT; i++) {
        if (strcmp(prng_list[i]->name, name) == 0)
            return prng_list[i];
    }
    return 0;
}

const prng_ops_t *crypto_prng_first(void) { return prng_list[0]; }

const prng_ops_t *crypto_prng_next(const prng_ops_t *cur)
{
    size_t i;
    for (i = 0; i < PRNG_COUNT; i++) {
        if (prng_list[i] == cur && i + 1 < PRNG_COUNT)
            return prng_list[i + 1];
    }
    return 0;
}
