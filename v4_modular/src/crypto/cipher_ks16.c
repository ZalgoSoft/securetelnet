#include "crypto/cipher.h"

static void ks16_xor(const kdf_ops_t *kdf, uint16_t S, uint16_t ctr, uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        uint16_t k = kdf->ks16(S, (uint16_t)(ctr + i));
        uint8_t b = (uint8_t)((k ^ (k >> 8)) & 0xFF);
        buf[i] ^= b;
    }
}

const cipher_ops_t cipher_ks16_ops = {
    "ks16",
    ks16_xor
};
