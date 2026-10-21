#include "compress.h"
#include <string.h>

static const compress_ops_t *compress_list[] = {
    &compress_none_ops,
    &compress_rle_ops,
#ifdef HAVE_LZ4
    &compress_lz4_ops
#endif
};

#define COMPRESS_COUNT (sizeof(compress_list)/sizeof(compress_list[0]))

const compress_ops_t *compress_find(const char *name)
{
    size_t i;
    for (i = 0; i < COMPRESS_COUNT; i++) {
        if (strcmp(compress_list[i]->name, name) == 0)
            return compress_list[i];
    }
    return 0;
}

const compress_ops_t *compress_first(void) { return compress_list[0]; }

const compress_ops_t *compress_next(const compress_ops_t *cur)
{
    size_t i;
    for (i = 0; i < COMPRESS_COUNT; i++) {
        if (compress_list[i] == cur && i + 1 < COMPRESS_COUNT)
            return compress_list[i + 1];
    }
    return 0;
}
