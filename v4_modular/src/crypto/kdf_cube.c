#include "crypto/kdf.h"
#include "crypto/field.h"

static uint16_t cube_ks16(uint16_t S, uint16_t ctr)
{
    uint32_t v = (uint32_t)((S ^ ctr) | 1u) % crypto_P;
    uint32_t r = (v * v) % crypto_P;
    r = (r * v) % crypto_P;
    return (uint16_t)r;
}

static uint8_t cube_byte(uint16_t S, uint16_t ctr)
{
    uint16_t v = cube_ks16(S, ctr);
    return (uint8_t)((v ^ (v >> 8)) & 0xFF);
}

const kdf_ops_t kdf_cube_ops = {
    "cube",
    cube_ks16,
    cube_byte
};
