#include "compress.h"
#include <string.h>

#ifdef HAVE_LZ4
#include <lz4.h>

static int lz4_compress_impl(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len)
{
    int r;
    if (in_len > (size_t)LZ4_MAX_INPUT_SIZE) return -1;
    r = LZ4_compress_default((const char *)in, (char *)out, (int)in_len, (int)*out_len);
    if (r <= 0) return -1;
    *out_len = (size_t)r;
    return 0;
}

static int lz4_decompress_impl(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len)
{
    int r = LZ4_decompress_safe((const char *)in, (char *)out, (int)in_len, (int)*out_len);
    if (r < 0) return -1;
    *out_len = (size_t)r;
    return 0;
}

const compress_ops_t compress_lz4_ops = {
    "lz4",
    lz4_compress_impl,
    lz4_decompress_impl
};
#else
static int lz4_compress_impl(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len)
{
    (void)in; (void)in_len; (void)out; (void)out_len;
    return -1;
}
static int lz4_decompress_impl(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len)
{
    (void)in; (void)in_len; (void)out; (void)out_len;
    return -1;
}
const compress_ops_t compress_lz4_ops = {
    "lz4",
    lz4_compress_impl,
    lz4_decompress_impl
};
#endif
