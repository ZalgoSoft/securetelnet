#include "crypto/context.h"
#include "crypto/field.h"
#include <string.h>

int crypto_init(crypto_ctx_t *ctx, const char *dh, const char *kdf, const char *cipher,
                const char *mac, const char *prng, const char *auth, int schnorr_cache)
{
    if (!ctx) return -1;
    memset(ctx, 0, sizeof(*ctx));
    ctx->dh = crypto_find_dh(dh);
    ctx->kdf = crypto_find_kdf(kdf);
    ctx->cipher = crypto_find_cipher(cipher);
    ctx->mac = crypto_find_mac(mac);
    ctx->prng = crypto_find_prng(prng);
    ctx->auth = crypto_find_auth(auth);
    if (!ctx->dh || !ctx->kdf || !ctx->cipher || !ctx->mac || !ctx->prng || !ctx->auth)
        return -1;
    ctx->schnorr_cache = schnorr_cache;
    ctx->G = crypto_find_generator();
    if (ctx->G == 0) return -1;
    return 0;
}

void crypto_free(crypto_ctx_t *ctx)
{
    if (!ctx) return;
    memset(ctx, 0, sizeof(*ctx));
}
