#include "compress.h"
#include <string.h>

static int none_compress(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len)
{
    if (*out_len < in_len) return -1;
    memcpy(out, in, in_len);
    *out_len = in_len;
    return 0;
}

static int none_decompress(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len)
{
    if (*out_len < in_len) return -1;
    memcpy(out, in, in_len);
    *out_len = in_len;
    return 0;
}

const compress_ops_t compress_none_ops = {
    "none",
    none_compress,
    none_decompress
};
