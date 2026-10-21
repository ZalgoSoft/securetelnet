#include "compress.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(void)
{
    const compress_ops_t *z;
    uint8_t in[4096], out[8192];
    size_t olen;
    int i;
    for (i = 0; i < (int)sizeof(in); i++) in[i] = (uint8_t)((i * 7) & 0xFF);
    for (z = compress_first(); z; z = compress_next(z)) {
        clock_t t0 = clock();
        int r;
        olen = sizeof(out);
        r = z->compress(in, sizeof(in), out, &olen);
        printf("compress=%s r=%d olen=%zu time=%.2f ms\n", z->name, r, olen,
               (double)(clock() - t0) / CLOCKS_PER_SEC * 1000.0);
    }
    return 0;
}
