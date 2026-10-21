#ifndef CRYPTO_AUTH_H
#define CRYPTO_AUTH_H

#include <stdint.h>
#include "kdf.h"

typedef struct auth_ops {
    const char *name;
    int (*server)(const kdf_ops_t *kdf, uint16_t S, uint16_t priv, uint16_t *challenge);
    int (*client)(const kdf_ops_t *kdf, uint16_t S, uint16_t priv, uint16_t challenge,
                  uint16_t *out1, uint16_t *out2);
} auth_ops_t;

extern const auth_ops_t auth_schnorr_ops;
extern const auth_ops_t auth_hmac_ops;

const auth_ops_t *crypto_find_auth(const char *name);
const auth_ops_t *crypto_auth_first(void);
const auth_ops_t *crypto_auth_next(const auth_ops_t *cur);

uint16_t crypto_auth_schnorr_challenge(uint16_t S, uint16_t fresh);
int crypto_auth_schnorr_verify(uint16_t S, uint16_t pub, uint16_t c, uint16_t R, uint16_t s);
int crypto_auth_schnorr_prove(uint16_t S, uint16_t priv, uint16_t c, uint16_t *outR, uint16_t *outs);

#endif
