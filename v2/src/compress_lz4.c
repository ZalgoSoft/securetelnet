#include "compress.h"

#ifdef HAVE_LZ4
#include <lz4.h>

int lz4_compress_wrap(const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap) {
    int r = LZ4_compress_default((const char*)in, (char*)out, (int)inlen, (int)outcap);
    return r > 0 ? r : -1;
}

int lz4_decompress_wrap(const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap) {
    int r = LZ4_decompress_safe((const char*)in, (char*)out, (int)inlen, (int)outcap);
    return r >= 0 ? r : -1;
}
#else
int lz4_compress_wrap(const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap) {
    (void)in; (void)inlen; (void)out; (void)outcap;
    return -1;
}
int lz4_decompress_wrap(const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap) {
    (void)in; (void)inlen; (void)out; (void)outcap;
    return -1;
}
#endif

int compress_buf(int mode, const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap) {
    if (mode == 1) return rle_compress(in, inlen, out, outcap);
    if (mode == 2) return lz4_compress_wrap(in, inlen, out, outcap);
    if (inlen > outcap) return -1;
    for (size_t i = 0; i < inlen; i++) out[i] = in[i];
    return (int)inlen;
}

int decompress_buf(int mode, const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap) {
    if (mode == 1) return rle_decompress(in, inlen, out, outcap);
    if (mode == 2) return lz4_decompress_wrap(in, inlen, out, outcap);
    if (inlen > outcap) return -1;
    for (size_t i = 0; i < inlen; i++) out[i] = in[i];
    return (int)inlen;
}
