#include "app.h"
#include "crypto/field.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

int app_keygen(const char *priv_path, const char *pub_path)
{
    uint32_t seed = (uint32_t)time(0) ^ ((uint32_t)getpid() << 16) ^ (uint32_t)clock();
    uint16_t priv = (uint16_t)(1 + seed % (crypto_P - 2));
    uint16_t pub = crypto_modpow(crypto_G, priv, crypto_P);
    FILE *f = fopen(priv_path, "w");
    if (!f) { perror("fopen"); return 1; }
    fprintf(f, "%04x\n", priv);
    fclose(f);
    f = fopen(pub_path, "w");
    if (!f) { perror("fopen"); return 1; }
    fprintf(f, "%04x\n", pub);
    fclose(f);
    return 0;
}
