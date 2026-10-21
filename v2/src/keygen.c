#include "keygen.h"
#include "algo.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

int keygen_run(const char *privpath, const char *pubpath) {
    uint32_t seed = (uint32_t)time(NULL) ^ ((uint32_t)getpid() << 16) ^ (uint32_t)clock();
    algo_config_t cfg;
    algo_config_default(&cfg);
    uint16_t priv = (uint16_t)(1 + (prng_next(&seed, &cfg) % (P - 2)));
    uint16_t pub = modpow(algo_g(), priv);
    FILE *f = fopen(privpath, "w");
    if (!f) { perror("fopen priv"); return 1; }
    fprintf(f, "%04X\n", priv);
    fclose(f);
    f = fopen(pubpath, "w");
    if (!f) { perror("fopen pub"); return 1; }
    fprintf(f, "%04X\n", pub);
    fclose(f);
    printf("priv = %04X -> %s\n", priv, privpath);
    printf("pub  = %04X -> %s\n", pub, pubpath);
    return 0;
}
