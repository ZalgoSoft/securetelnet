#include "crypto/kdf.h"
#include "crypto/field.h"

static uint16_t double_ks16(uint16_t S, uint16_t ctr)
{
    uint32_t v = (uint32_t)((S ^ ctr) | 1u) % crypto_P;
    uint32_t r = (v * v) % crypto_P;
    r = (r * v) % crypto_P;
    v = (r ^ (uint32_t)(ctr ^ 0xAAAAu)) | 1u;
    v %= crypto_P;
    r = (v * v) % crypto_P;
    r = (r * v) % crypto_P;
    return (uint16_t)r;
}

static uint8_t double_byte(uint16_t S, uint16_t ctr)
{
    uint16_t v = double_ks16(S, ctr);
    return (uint8_t)((v ^ (v >> 8)) & 0xFF);
}

const kdf_ops_t kdf_double_ops = {
    "double",
    double_ks16,
    double_byte
};
