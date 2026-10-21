#ifndef COMPRESS_H
#define COMPRESS_H

#include <stdint.h>
#include <stddef.h>

int rle_compress(const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap);
int rle_decompress(const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap);

int lz4_compress_wrap(const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap);
int lz4_decompress_wrap(const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap);

int compress_buf(int mode, const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap);
int decompress_buf(int mode, const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap);

#endif
