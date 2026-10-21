#include "crypto/auth.h"
#include "crypto/field.h"

static int hmac_server(const kdf_ops_t *kdf, uint16_t S, uint16_t priv, uint16_t *challenge)
{
    *challenge = kdf->ks16(S, (uint16_t)(priv ^ 0xA5A5));
    if (*challenge == 0) *challenge = 1;
    return 0;
}

static int hmac_client(const kdf_ops_t *kdf, uint16_t S, uint16_t priv, uint16_t c,
                       uint16_t *out1, uint16_t *out2)
{
    uint16_t pub = crypto_modpow(crypto_G, priv, crypto_P);
    *out1 = kdf->ks16(S, (uint16_t)(pub ^ c));
    *out2 = 0;
    return 0;
}

const auth_ops_t auth_hmac_ops = {
    "hmac",
    hmac_server,
    hmac_client
};
