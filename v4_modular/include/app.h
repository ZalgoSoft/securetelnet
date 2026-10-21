#ifndef APP_H
#define APP_H
#include "common.h"
#include "proto.h"

#include "negotiation.h"
#include "crypto/context.h"
#include "compress.h"
#include "mode.h"
#include "session.h"

typedef struct app_config {
    negotiation_params_t neg;
    crypto_ctx_t crypto;
    const compress_ops_t *compress;
    const mode_ops_t *mode;
    mode_args_t mode_args;
    const char *session_dir;
    int debug;
} app_config_t;

int app_run_server(int listen_port, const char *auth_keys, app_config_t *cfg);
int app_run_client(const char *host, int port, const char *priv_key, app_config_t *cfg);
int app_keygen(const char *priv_path, const char *pub_path);

#endif
