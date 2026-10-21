#include "crypto/kdf.h"

static uint16_t byte_ks16(uint16_t S, uint16_t ctr)
{
    return (uint16_t)((S ^ ctr) & 0xFFu);
}

static uint8_t byte_byte(uint16_t S, uint16_t ctr)
{
    return (uint8_t)((S ^ ctr) & 0xFFu);
}

const kdf_ops_t kdf_byte_ops = {
    "byte",
    byte_ks16,
    byte_byte
};
