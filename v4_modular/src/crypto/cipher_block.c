#include "crypto/cipher.h"

static void block_xor(const kdf_ops_t *kdf, uint16_t S, uint16_t ctr, uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i += 2) {
        uint16_t k = kdf->ks16(S, (uint16_t)(ctr + (uint16_t)(i / 2)));
        buf[i] ^= (uint8_t)(k & 0xFF);
        if (i + 1 < len)
            buf[i + 1] ^= (uint8_t)((k >> 8) & 0xFF);
    }
}

const cipher_ops_t cipher_block_ops = {
    "block",
    block_xor
};
