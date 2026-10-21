#include "algo.h"
#include "proto.h"
#include "keygen.h"
#include "server.h"
#include "client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog) {
    fprintf(stderr,
        "usage:\n"
        "  %s keygen <privfile> <pubfile>\n"
        "  %s server <port> <authorized_keys> [--mode chat|shell|file] [--shell /bin/sh]\n"
        "       [--kdf cube|byte|double] [--cipher ks16|raw|block]\n"
        "       [--auth schnorr|hmac] [--schnorr plain|cache]\n"
        "       [--mac ks16|precalc] [--prng xorshift|mask|clock]\n"
        "       [--compress none|rle|lz4] [--dh normal|test] [--session-dir DIR]\n"
        "       [--overwrite | --no-overwrite]   (default: --no-overwrite)\n"
        "  %s client <host> <port> <privfile> [--mode chat|shell|file] [--file-cmd 'get remote local'|'put local remote']\n"
        "       [--kdf ...] [--cipher ...] [--auth ...] [--schnorr ...]\n"
        "       [--mac ...] [--prng ...] [--compress ...] [--dh ...] [--session-dir DIR]\n",
        prog, prog, prog);
}

static int parse_algo_flags(int argc, char **argv, algo_config_t *cfg,
                            int *mode, const char **shell, const char **session_dir,
                            const char **file_cmd, int *overwrite) {
    *mode = MODE_CHAT;
    *shell = "/bin/sh";
    *session_dir = NULL;
    *file_cmd = NULL;
    *overwrite = 0;
    algo_config_default(cfg);
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--mode") && i + 1 < argc) {
            const char *v = argv[++i];
            if (!strcmp(v, "chat")) *mode = MODE_CHAT;
            else if (!strcmp(v, "shell")) *mode = MODE_SHELL;
            else if (!strcmp(v, "file")) *mode = MODE_FILE;
            else return -1;
        } else if (!strcmp(a, "--shell") && i + 1 < argc) *shell = argv[++i];
        else if (!strcmp(a, "--session-dir") && i + 1 < argc) *session_dir = argv[++i];
        else if (!strcmp(a, "--file-cmd") && i + 1 < argc) *file_cmd = argv[++i];
        else if (!strcmp(a, "--overwrite")) *overwrite = 1;
        else if (!strcmp(a, "--no-overwrite")) *overwrite = 0;
        else if (!strcmp(a, "--kdf") && i + 1 < argc) { int r = algo_parse_kdf(argv[++i]); if (r < 0) return -1; cfg->kdf_mode = r; }
        else if (!strcmp(a, "--cipher") && i + 1 < argc) { int r = algo_parse_cipher(argv[++i]); if (r < 0) return -1; cfg->cipher_mode = r; }
        else if (!strcmp(a, "--auth") && i + 1 < argc) { int r = algo_parse_auth(argv[++i]); if (r < 0) return -1; cfg->auth_mode = r; }
        else if (!strcmp(a, "--schnorr") && i + 1 < argc) { int r = algo_parse_schnorr(argv[++i]); if (r < 0) return -1; cfg->schnorr_cache = r; }
        else if (!strcmp(a, "--mac") && i + 1 < argc) { int r = algo_parse_mac(argv[++i]); if (r < 0) return -1; cfg->mac_mode = r; }
        else if (!strcmp(a, "--prng") && i + 1 < argc) { int r = algo_parse_prng(argv[++i]); if (r < 0) return -1; cfg->prng_mode = r; }
        else if (!strcmp(a, "--compress") && i + 1 < argc) { int r = algo_parse_compress(argv[++i]); if (r < 0) return -1; cfg->compress_mode = r; }
        else if (!strcmp(a, "--dh") && i + 1 < argc) { int r = algo_parse_dh(argv[++i]); if (r < 0) return -1; cfg->dh_mode = r; }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 1; }
    if (algo_self_test() != 0) { fprintf(stderr, "self-test failed\n"); return 1; }

    if (!strcmp(argv[1], "keygen")) {
        if (argc < 4) { usage(argv[0]); return 1; }
        return keygen_run(argv[2], argv[3]);
    }

    algo_config_t cfg;
    int mode, overwrite;
    const char *shell, *session_dir, *file_cmd;
    if (parse_algo_flags(argc, argv, &cfg, &mode, &shell, &session_dir,
                         &file_cmd, &overwrite) < 0) {
        fprintf(stderr, "bad arguments\n");
        usage(argv[0]);
        return 1;
    }

    if (!strcmp(argv[1], "server")) {
        if (argc < 4) { usage(argv[0]); return 1; }
        proto_params_t caps;
        proto_params_from_algo(&caps, &cfg);
        int port = atoi(argv[2]);
        return server_run(port, argv[3], mode, shell, &caps, session_dir, overwrite);
    }
    if (!strcmp(argv[1], "client")) {
        if (argc < 5) { usage(argv[0]); return 1; }
        proto_params_t caps;
        proto_params_from_algo(&caps, &cfg);
        int port = atoi(argv[3]);
        return client_run(argv[2], port, argv[4], mode, shell, &caps,
                          session_dir, file_cmd, overwrite);
    }
    usage(argv[0]);
    return 1;
}
