#ifndef CRYPTO_DH_H
#define CRYPTO_DH_H

#include <stdint.h>

typedef struct dh_ops {
    const char *name;
    int (*client)(uint16_t *out_A, uint16_t *out_nonce, uint16_t *out_priv);
    int (*server)(uint16_t peer_A, uint16_t *out_B, uint16_t *out_nonce, uint16_t *out_priv);
} dh_ops_t;

extern const dh_ops_t dh_normal_ops;
extern const dh_ops_t dh_test_ops;

const dh_ops_t *crypto_find_dh(const char *name);
const dh_ops_t *crypto_dh_first(void);
const dh_ops_t *crypto_dh_next(const dh_ops_t *cur);

#endif
