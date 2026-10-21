#ifndef MODE_FILE_TRANSFER_H
#define MODE_FILE_TRANSFER_H

#include "proto.h"
#include "session.h"
#include <stdint.h>

int do_put(proto_ctx_t *p, session_t *s, const char *local, const char *remote);
int do_get(proto_ctx_t *p, session_t *s, const char *remote, const char *local);
int serve_file(proto_ctx_t *p, session_t *s, int overwrite);

#endif
