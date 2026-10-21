#include "crypto/mac.h"

static uint16_t ks16_tag(const kdf_ops_t *kdf, uint16_t S, uint16_t ctr)
{
    return kdf->ks16(S, (uint16_t)(ctr ^ 0xFFFF));
}

const mac_ops_t mac_ks16_ops = {
    "ks16",
    ks16_tag
};
