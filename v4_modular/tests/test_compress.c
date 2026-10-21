#include "compress.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(void)
{
    const compress_ops_t *c;
    unsigned seed = (unsigned)time(0) ^ (unsigned)clock();
    uint8_t in[1024], enc[2048], dec[2048];
    size_t i;
    printf("seed=%u\n", seed);
    srand(seed);
    for (i = 0; i < sizeof(in); i++) in[i] = (uint8_t)(rand() & 0xFF);
    for (c = compress_first(); c; c = compress_next(c)) {
        size_t elen = sizeof(enc), dlen = sizeof(dec);
        printf("compress=%s\n", c->name);
        if (c->compress(in, sizeof(in), enc, &elen) != 0) {
            printf("  compress failed\n");
            continue;
        }
        if (c->decompress(enc, elen, dec, &dlen) != 0) {
            printf("  decompress failed\n");
            continue;
        }
        printf("  in=%zu enc=%zu dec=%zu\n", sizeof(in), elen, dlen);
    }
    return 0;
}
