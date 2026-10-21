#include "crypto/auth.h"
#include "crypto/field.h"
#include <stdlib.h>

uint16_t crypto_auth_schnorr_challenge(uint16_t S, uint16_t fresh)
{
    uint16_t c = (uint16_t)((S ^ fresh ^ (uint16_t)(S >> 3)) & 0xFFFF);
    if (c == 0) c = 1;
    return c;
}

int crypto_auth_schnorr_prove(uint16_t S, uint16_t priv, uint16_t c, uint16_t *outR, uint16_t *outs)
{
    uint32_t span = (uint32_t)(crypto_P - 2);
    uint16_t r = (uint16_t)(1 + rand() % span);
    uint16_t R = crypto_modpow(crypto_G, r, crypto_P);
    uint32_t s = ((uint32_t)r + (uint32_t)c * priv) % (crypto_P - 1);
    *outR = R;
    *outs = (uint16_t)s;
    (void)S;
    return 0;
}

int crypto_auth_schnorr_verify(uint16_t S, uint16_t pub, uint16_t c, uint16_t R, uint16_t s)
{
    uint16_t lhs, rhs_part, rhs;
    if (R == 0 || R >= crypto_P) return -1;
    if (pub == 0 || pub >= crypto_P) return -1;
    (void)S;
    lhs = crypto_modpow(crypto_G, s, crypto_P);
    rhs_part = crypto_modpow(pub, c, crypto_P);
    rhs = (uint16_t)(((uint32_t)R * rhs_part) % crypto_P);
    return lhs == rhs ? 0 : -1;
}

static int schnorr_server(const kdf_ops_t *kdf, uint16_t S, uint16_t priv, uint16_t *challenge)
{
    uint16_t fresh = kdf->ks16(S, (uint16_t)rand());
    *challenge = crypto_auth_schnorr_challenge(S, fresh);
    (void)priv;
    return 0;
}

static int schnorr_client(const kdf_ops_t *kdf, uint16_t S, uint16_t priv, uint16_t c,
                          uint16_t *out1, uint16_t *out2)
{
    (void)kdf;
    return crypto_auth_schnorr_prove(S, priv, c, out1, out2);
}

const auth_ops_t auth_schnorr_ops = {
    "schnorr",
    schnorr_server,
    schnorr_client
};
