#include "mode.h"
#include "transfer.h"
#include "path_safe.h"
#include "proto.h"
#include "session.h"
#include <string.h>
#include <stdio.h>

static int file_server(proto_ctx_t *p, session_t *s, const mode_args_t *a)
{
    session_log(s, "file server start");
    return serve_file(p, s, a->overwrite);
}

static int file_client(proto_ctx_t *p, session_t *s, const mode_args_t *a)
{
    char op[8], local[2048], remote[2048];
    int n;
    if (!a->file_cmd) { fprintf(stderr, "file-cmd required\n"); return -1; }
    n = sscanf(a->file_cmd, "%7s %2047s %2047s", op, local, remote);
    if (n != 3) { fprintf(stderr, "invalid file-cmd\n"); return -1; }
    if (strcmp(op, "put") == 0)
        return do_put(p, s, local, remote);
    if (strcmp(op, "get") == 0)
        return do_get(p, s, local, remote);
    fprintf(stderr, "unknown file op\n");
    return -1;
}

const mode_ops_t mode_file_ops = {
    "file",
    file_server,
    file_client
};
