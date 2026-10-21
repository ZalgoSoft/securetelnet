#ifndef MODE_H
#define MODE_H

#include <stdint.h>

typedef struct proto_ctx proto_ctx_t;
typedef struct session_t session_t;

typedef struct mode_args {
    const char *shell_path;
    const char *file_cmd;
    int overwrite;
} mode_args_t;

typedef struct mode_ops {
    const char *name;
    int (*server)(proto_ctx_t *p, session_t *s, const mode_args_t *a);
    int (*client)(proto_ctx_t *p, session_t *s, const mode_args_t *a);
} mode_ops_t;

extern const mode_ops_t mode_chat_ops;
extern const mode_ops_t mode_shell_ops;
extern const mode_ops_t mode_file_ops;

const mode_ops_t *mode_find(const char *name);
const mode_ops_t *mode_first(void);
const mode_ops_t *mode_next(const mode_ops_t *cur);

#endif
