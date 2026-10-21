#ifndef CRYPTO_MAC_H
#define CRYPTO_MAC_H

#include <stdint.h>
#include "kdf.h"

typedef struct mac_ops {
    const char *name;
    uint16_t (*tag)(const kdf_ops_t *kdf, uint16_t S, uint16_t ctr);
} mac_ops_t;

extern const mac_ops_t mac_ks16_ops;
extern const mac_ops_t mac_precalc_ops;

const mac_ops_t *crypto_find_mac(const char *name);
const mac_ops_t *crypto_mac_first(void);
const mac_ops_t *crypto_mac_next(const mac_ops_t *cur);

#endif
