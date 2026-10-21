#ifndef CLIENT_H
#define CLIENT_H

#include "algo.h"
#include "proto.h"

int client_run(const char *host, int port, const char *privfile, int mode,
               const char *shell, const proto_params_t *caps, const char *session_dir,
               const char *file_cmd, int overwrite);

#endif
