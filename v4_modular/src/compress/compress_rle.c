#include "compress.h"
#include <string.h>

static int rle_compress(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len)
{
    size_t i = 0, o = 0;
    while (i < in_len) {
        uint8_t b = in[i];
        size_t run = 1;
        while (i + run < in_len && in[i + run] == b && run < 255) run++;
        if (o + 2 > *out_len) return -1;
        out[o++] = (uint8_t)run;
        out[o++] = b;
        i += run;
    }
    *out_len = o;
    return 0;
}

static int rle_decompress(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len)
{
    size_t i = 0, o = 0;
    while (i + 1 < in_len) {
        uint8_t run = in[i++];
        uint8_t b = in[i++];
        if (o + run > *out_len) return -1;
        memset(out + o, b, run);
        o += run;
    }
    if (i != in_len) return -1;
    *out_len = o;
    return 0;
}

const compress_ops_t compress_rle_ops = {
    "rle",
    rle_compress,
    rle_decompress
};
