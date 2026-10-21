#include "crypto/cipher.h"

static void raw_xor(const kdf_ops_t *kdf, uint16_t S, uint16_t ctr, uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        uint16_t k = kdf->ks16(S, (uint16_t)(ctr + i));
        buf[i] ^= (uint8_t)(k & 0xFF);
    }
}

const cipher_ops_t cipher_raw_ops = {
    "raw",
    raw_xor
};
