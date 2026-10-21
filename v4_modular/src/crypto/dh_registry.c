#include "crypto/dh.h"
#include <string.h>

static const dh_ops_t *dh_list[] = {
    &dh_normal_ops,
    &dh_test_ops
};

#define DH_COUNT (sizeof(dh_list)/sizeof(dh_list[0]))

const dh_ops_t *crypto_find_dh(const char *name)
{
    size_t i;
    for (i = 0; i < DH_COUNT; i++) {
        if (strcmp(dh_list[i]->name, name) == 0)
            return dh_list[i];
    }
    return 0;
}

const dh_ops_t *crypto_dh_first(void)
{
    return dh_list[0];
}

const dh_ops_t *crypto_dh_next(const dh_ops_t *cur)
{
    size_t i;
    for (i = 0; i < DH_COUNT; i++) {
        if (dh_list[i] == cur && i + 1 < DH_COUNT)
            return dh_list[i + 1];
    }
    return 0;
}
