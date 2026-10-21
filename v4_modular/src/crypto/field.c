#include "crypto/field.h"

const uint16_t crypto_P = FIELD_P;
const uint16_t crypto_D_INV = FIELD_D_INV;
uint16_t crypto_G = 0;

uint16_t crypto_modpow(uint16_t base, uint16_t exp, uint16_t mod)
{
    uint32_t result = 1u;
    uint32_t b = base % mod;
    uint32_t e = exp;
    while (e) {
        if (e & 1u)
            result = (result * b) % mod;
        b = (b * b) % mod;
        e >>= 1;
    }
    return (uint16_t)result;
}

static int divides(uint16_t n, uint16_t q)
{
    return n % q == 0;
}

uint16_t crypto_find_generator(void)
{
    static const uint16_t factors[] = {2, 7, 31, 151};
    uint32_t g;
    for (g = 2; g < crypto_P; g++) {
        int ok = 1;
        size_t i;
        for (i = 0; i < sizeof(factors)/sizeof(factors[0]); i++) {
            uint16_t q = factors[i];
            uint16_t e = (uint16_t)((crypto_P - 1) / q);
            if (crypto_modpow((uint16_t)g, e, crypto_P) == 1) {
                ok = 0;
                break;
            }
        }
        if (ok)
            return (uint16_t)g;
    }
    return 0;
}

uint16_t crypto_inv3(void)
{
    return crypto_D_INV;
}
