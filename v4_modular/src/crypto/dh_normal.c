#include "crypto/dh.h"
#include "crypto/field.h"
#include <stdlib.h>

static uint16_t pick_priv(uint16_t lo, uint16_t hi)
{
    uint32_t span = (uint32_t)(hi - lo + 1);
    return (uint16_t)(lo + (uint16_t)(rand() % span));
}

static int normal_client(uint16_t *out_A, uint16_t *out_nonce, uint16_t *out_priv)
{
    uint16_t a = pick_priv(1, crypto_P - 2);
    *out_priv = a;
    *out_A = crypto_modpow(crypto_G, a, crypto_P);
    *out_nonce = (uint16_t)(rand() & 0xFFFF);
    return 0;
}

static int normal_server(uint16_t peer_A, uint16_t *out_B, uint16_t *out_nonce, uint16_t *out_priv)
{
    uint16_t b;
    if (peer_A == 0 || peer_A == 1 || peer_A == crypto_P - 1 || peer_A >= crypto_P)
        return -1;
    b = pick_priv(1, crypto_P - 2);
    *out_priv = b;
    *out_B = crypto_modpow(crypto_G, b, crypto_P);
    *out_nonce = (uint16_t)(rand() & 0xFFFF);
    return 0;
}

const dh_ops_t dh_normal_ops = {
    "normal",
    normal_client,
    normal_server
};
