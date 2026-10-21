#include "app.h"
#include "crypto/field.h"
#include "crypto/context.h"
#include "crypto/dh.h"
#include "crypto/kdf.h"
#include "crypto/cipher.h"
#include "crypto/mac.h"
#include "crypto/prng.h"
#include "crypto/auth.h"
#include "compress.h"
#include "mode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int self_test(void)
{
    uint16_t g;
    int i;
    if ((uint32_t)((crypto_P - 1) % 3) == 0) return -1;
    if ((uint32_t)((uint32_t)crypto_D_INV * 3u % (crypto_P - 1)) != 1u) return -1;
    g = crypto_find_generator();
    if (g == 0) return -1;
    crypto_G = g;
    for (i = 1; i < 100; i++) {
        uint16_t v = (uint16_t)((i | 1u) % crypto_P);
        uint32_t c = (uint32_t)v * v % crypto_P;
        c = c * v % crypto_P;
        if (c >= crypto_P) return -1;
    }
    printf("self-test ok: generator G=%u\n", g);
    return 0;
}

static void help(const char *prog)
{
    const dh_ops_t *dh;
    const kdf_ops_t *kdf;
    const cipher_ops_t *c;
    const mac_ops_t *m;
    const prng_ops_t *p;
    const auth_ops_t *a;
    const compress_ops_t *z;
    const mode_ops_t *mo;
    printf("Usage:\n");
    printf("  %s keygen PRIV PUB\n", prog);
    printf("  %s server PORT AUTHORIZED_KEYS [options]\n", prog);
    printf("  %s client HOST PORT PRIVATE_KEY [options]\n", prog);
    printf("\nModes:\n");
    printf("  chat   interactive chat (default)\n");
    printf("  shell  remote shell\n");
    printf("  file   file transfer (put/get)\n");
    printf("\nAlgorithms:\n");
    printf("  KDF:    ");
    for (kdf = crypto_kdf_first(); kdf; kdf = crypto_kdf_next(kdf)) printf("%s ", kdf->name);
    printf("\n  Cipher: ");
    for (c = crypto_cipher_first(); c; c = crypto_cipher_next(c)) printf("%s ", c->name);
    printf("\n  MAC:    ");
    for (m = crypto_mac_first(); m; m = crypto_mac_next(m)) printf("%s ", m->name);
    printf("\n  PRNG:   ");
    for (p = crypto_prng_first(); p; p = crypto_prng_next(p)) printf("%s ", p->name);
    printf("\n  Auth:   ");
    for (a = crypto_auth_first(); a; a = crypto_auth_next(a)) printf("%s ", a->name);
    printf("\n  DH:     ");
    for (dh = crypto_dh_first(); dh; dh = crypto_dh_next(dh)) printf("%s ", dh->name);
    printf("\n  Compress: ");
    for (z = compress_first(); z; z = compress_next(z)) printf("%s ", z->name);
    printf("\n  Modes:  ");
    for (mo = mode_first(); mo; mo = mode_next(mo)) printf("%s ", mo->name);
    printf("\n\nDefaults:\n");
    printf("  --mode chat  --shell /bin/sh  --kdf cube  --cipher ks16\n");
    printf("  --auth schnorr  --schnorr plain  --mac ks16  --prng xorshift\n");
    printf("  --compress none  --dh normal  --no-overwrite  --debug off\n");
    printf("\nExit codes: 0 success, 1 error\n");
}

static int parse_common(int argc, char **argv, int start, app_config_t *cfg, int is_server)
{
    int i;
    int allow_test = 0;
    cfg->mode = mode_find("chat");
    cfg->mode_args.shell_path = "/bin/sh";
    cfg->mode_args.overwrite = 0;
    cfg->neg.version = PROTO_VERSION;
    cfg->neg.schnorr_cache = 0;
    for (i = start; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--mode") && i + 1 < argc) {
            cfg->mode = mode_find(argv[++i]);
            if (!cfg->mode) { fprintf(stderr, "unknown mode\n"); return -1; }
        } else if (!strcmp(a, "--shell") && i + 1 < argc) {
            cfg->mode_args.shell_path = argv[++i];
        } else if (!strcmp(a, "--session-dir") && i + 1 < argc) {
            cfg->session_dir = argv[++i];
        } else if (!strcmp(a, "--kdf") && i + 1 < argc) {
            cfg->neg.kdf = negotiation_kdf_id(argv[++i]);
            if (cfg->neg.kdf == 0xFF) { fprintf(stderr, "unknown kdf\n"); return -1; }
        } else if (!strcmp(a, "--cipher") && i + 1 < argc) {
            cfg->neg.cipher = negotiation_cipher_id(argv[++i]);
            if (cfg->neg.cipher == 0xFF) { fprintf(stderr, "unknown cipher\n"); return -1; }
        } else if (!strcmp(a, "--auth") && i + 1 < argc) {
            cfg->neg.auth = negotiation_auth_id(argv[++i]);
            if (cfg->neg.auth == 0xFF) { fprintf(stderr, "unknown auth\n"); return -1; }
        } else if (!strcmp(a, "--schnorr") && i + 1 < argc) {
            const char *v = argv[++i];
            if (!strcmp(v, "cache")) cfg->neg.schnorr_cache = 1;
            else if (!strcmp(v, "plain")) cfg->neg.schnorr_cache = 0;
            else { fprintf(stderr, "unknown schnorr mode\n"); return -1; }
        } else if (!strcmp(a, "--mac") && i + 1 < argc) {
            cfg->neg.mac = negotiation_mac_id(argv[++i]);
            if (cfg->neg.mac == 0xFF) { fprintf(stderr, "unknown mac\n"); return -1; }
        } else if (!strcmp(a, "--prng") && i + 1 < argc) {
            cfg->neg.prng = negotiation_prng_id(argv[++i]);
            if (cfg->neg.prng == 0xFF) { fprintf(stderr, "unknown prng\n"); return -1; }
        } else if (!strcmp(a, "--compress") && i + 1 < argc) {
            cfg->neg.compress = negotiation_compress_id(argv[++i]);
            if (cfg->neg.compress == 0xFF) { fprintf(stderr, "unknown compress\n"); return -1; }
        } else if (!strcmp(a, "--dh") && i + 1 < argc) {
            cfg->neg.dh = negotiation_dh_id(argv[++i]);
            if (cfg->neg.dh == 0xFF) { fprintf(stderr, "unknown dh\n"); return -1; }
        } else if (!strcmp(a, "--overwrite")) {
            cfg->mode_args.overwrite = 1;
        } else if (!strcmp(a, "--no-overwrite")) {
            cfg->mode_args.overwrite = 0;
        } else if (!strcmp(a, "--debug")) {
            cfg->debug = 1;
        } else if (!strcmp(a, "--allow-test")) {
            allow_test = 1;
        } else if (!strcmp(a, "--file-cmd") && i + 1 < argc) {
            cfg->mode_args.file_cmd = argv[++i];
        } else {
            fprintf(stderr, "unknown option: %s\n", a);
            return -1;
        }
    }
    if (is_server) {
        uint8_t test_id = negotiation_dh_id("test");
        if (cfg->neg.dh == test_id && !allow_test) {
            fprintf(stderr, "server rejects --dh test unless --allow-test is given\n");
            return -1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2 || !strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
        help(argv[0]);
        return 0;
    }
    if (self_test() != 0) { fprintf(stderr, "self test failed\n"); return 1; }
    if (!strcmp(argv[1], "keygen")) {
        if (argc < 4) { fprintf(stderr, "keygen PRIV PUB\n"); return 1; }
        return app_keygen(argv[2], argv[3]);
    }
    app_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    if (!strcmp(argv[1], "server")) {
        int port;
        if (argc < 4) { fprintf(stderr, "server PORT AUTH_KEYS\n"); return 1; }
        port = atoi(argv[2]);
        if (parse_common(argc, argv, 4, &cfg, 1) != 0) return 1;
        return app_run_server(port, argv[3], &cfg);
    }
    if (!strcmp(argv[1], "client")) {
        int port;
        if (argc < 5) { fprintf(stderr, "client HOST PORT PRIV\n"); return 1; }
        port = atoi(argv[3]);
        if (parse_common(argc, argv, 5, &cfg, 0) != 0) return 1;
        return app_run_client(argv[2], port, argv[4], &cfg);
    }
    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 1;
}
