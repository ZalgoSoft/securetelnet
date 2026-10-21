#include "compress.h"

int rle_compress(const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap) {
    size_t o = 0, i = 0;
    while (i < inlen) {
        uint8_t v = in[i];
        size_t run = 1;
        while (i + run < inlen && in[i + run] == v && run < 255) run++;
        if (o + 2 > outcap) return -1;
        out[o++] = (uint8_t)run;
        out[o++] = v;
        i += run;
    }
    return (int)o;
}

int rle_decompress(const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap) {
    size_t o = 0, i = 0;
    while (i + 1 < inlen) {
        uint8_t run = in[i++];
        uint8_t v = in[i++];
        if (o + run > outcap) return -1;
        for (uint8_t k = 0; k < run; k++) out[o++] = v;
    }
    return (int)o;
}
