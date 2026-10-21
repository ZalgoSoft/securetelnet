#include "crypto/prng.h"

static uint16_t xorshift_next(uint32_t *state)
{
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return (uint16_t)(x & 0xFFFF);
}

const prng_ops_t prng_xorshift_ops = {
    "xorshift",
    xorshift_next
};
