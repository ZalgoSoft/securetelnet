#ifndef CRYPTO_CONTEXT_H
#define CRYPTO_CONTEXT_H

#include "dh.h"
#include "kdf.h"
#include "cipher.h"
#include "mac.h"
#include "prng.h"
#include "auth.h"

typedef struct crypto_ctx {
    const dh_ops_t *dh;
    const kdf_ops_t *kdf;
    const cipher_ops_t *cipher;
    const mac_ops_t *mac;
    const prng_ops_t *prng;
    const auth_ops_t *auth;
    int schnorr_cache;
    uint16_t G;
} crypto_ctx_t;

int crypto_init(crypto_ctx_t *ctx, const char *dh, const char *kdf, const char *cipher,
                const char *mac, const char *prng, const char *auth, int schnorr_cache);
void crypto_free(crypto_ctx_t *ctx);

#endif
