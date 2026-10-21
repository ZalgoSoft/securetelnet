#include "io.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

int main(void)
{
    int p[2];
    char buf[64];
    unsigned seed = (unsigned)time(0) ^ (unsigned)getpid() ^ (unsigned)clock();
    printf("seed=%u\n", seed);
    srand(seed);
    if (pipe(p) != 0) return 1;
    if (io_write_full(p[1], "hello", 5) != 5) return 1;
    if (io_read_full(p[0], buf, 5) != 5) return 1;
    printf("got: %.*s\n", 5, buf);
    close(p[0]); close(p[1]);
    return 0;
}
