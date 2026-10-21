#include "crypto/auth.h"
#include <string.h>

static const auth_ops_t *auth_list[] = {
    &auth_schnorr_ops,
    &auth_hmac_ops
};

#define AUTH_COUNT (sizeof(auth_list)/sizeof(auth_list[0]))

const auth_ops_t *crypto_find_auth(const char *name)
{
    size_t i;
    for (i = 0; i < AUTH_COUNT; i++) {
        if (strcmp(auth_list[i]->name, name) == 0)
            return auth_list[i];
    }
    return 0;
}

const auth_ops_t *crypto_auth_first(void) { return auth_list[0]; }

const auth_ops_t *crypto_auth_next(const auth_ops_t *cur)
{
    size_t i;
    for (i = 0; i < AUTH_COUNT; i++) {
        if (auth_list[i] == cur && i + 1 < AUTH_COUNT)
            return auth_list[i + 1];
    }
    return 0;
}
