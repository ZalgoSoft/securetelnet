#include "crypto/kdf.h"
#include <string.h>

static const kdf_ops_t *kdf_list[] = {
    &kdf_cube_ops,
    &kdf_byte_ops,
    &kdf_double_ops
};

#define KDF_COUNT (sizeof(kdf_list)/sizeof(kdf_list[0]))

const kdf_ops_t *crypto_find_kdf(const char *name)
{
    size_t i;
    for (i = 0; i < KDF_COUNT; i++) {
        if (strcmp(kdf_list[i]->name, name) == 0)
            return kdf_list[i];
    }
    return 0;
}

const kdf_ops_t *crypto_kdf_first(void) { return kdf_list[0]; }

const kdf_ops_t *crypto_kdf_next(const kdf_ops_t *cur)
{
    size_t i;
    for (i = 0; i < KDF_COUNT; i++) {
        if (kdf_list[i] == cur && i + 1 < KDF_COUNT)
            return kdf_list[i + 1];
    }
    return 0;
}
