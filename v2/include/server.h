#ifndef SERVER_H
#define SERVER_H

#include "algo.h"
#include "proto.h"

enum {
    MODE_CHAT = 0,
    MODE_SHELL = 1,
    MODE_FILE = 2,
};

int server_run(int port, const char *keyfile, int mode, const char *shell,
               const proto_params_t *caps, const char *session_dir);

#endif
