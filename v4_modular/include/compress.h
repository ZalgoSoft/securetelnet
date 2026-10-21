#ifndef COMPRESS_H
#define COMPRESS_H

#include <stdint.h>
#include <stddef.h>

typedef struct compress_ops {
    const char *name;
    int (*compress)(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);
    int (*decompress)(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);
} compress_ops_t;

extern const compress_ops_t compress_none_ops;
extern const compress_ops_t compress_rle_ops;
extern const compress_ops_t compress_lz4_ops;

const compress_ops_t *compress_find(const char *name);
const compress_ops_t *compress_first(void);
const compress_ops_t *compress_next(const compress_ops_t *cur);

#endif
