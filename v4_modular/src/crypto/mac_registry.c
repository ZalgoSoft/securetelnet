#include "crypto/mac.h"
#include <string.h>

static const mac_ops_t *mac_list[] = {
    &mac_ks16_ops,
    &mac_precalc_ops
};

#define MAC_COUNT (sizeof(mac_list)/sizeof(mac_list[0]))

const mac_ops_t *crypto_find_mac(const char *name)
{
    size_t i;
    for (i = 0; i < MAC_COUNT; i++) {
        if (strcmp(mac_list[i]->name, name) == 0)
            return mac_list[i];
    }
    return 0;
}

const mac_ops_t *crypto_mac_first(void) { return mac_list[0]; }

const mac_ops_t *crypto_mac_next(const mac_ops_t *cur)
{
    size_t i;
    for (i = 0; i < MAC_COUNT; i++) {
        if (mac_list[i] == cur && i + 1 < MAC_COUNT)
            return mac_list[i + 1];
    }
    return 0;
}
