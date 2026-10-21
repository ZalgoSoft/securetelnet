#include "crypto/mac.h"

static uint16_t precalc_tag(const kdf_ops_t *kdf, uint16_t S, uint16_t ctr)
{
    uint16_t a = kdf->ks16(S, ctr);
    uint16_t b = kdf->ks16(S, (uint16_t)(ctr ^ 0xFFFF));
    return (uint16_t)((a ^ b) & 0xFFFF);
}

const mac_ops_t mac_precalc_ops = {
    "precalc",
    precalc_tag
};
