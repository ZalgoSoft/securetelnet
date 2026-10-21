#include "crypto/prng.h"
#include <time.h>

static uint16_t clock_next(uint32_t *state)
{
    uint32_t x = *state ^ (uint32_t)clock();
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return (uint16_t)(x & 0xFFFF);
}

const prng_ops_t prng_clock_ops = {
    "clock",
    clock_next
};
