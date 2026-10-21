#ifndef MODE_FILE_PATH_SAFE_H
#define MODE_FILE_PATH_SAFE_H
#include <stddef.h>

int path_is_safe(const char *path);
int pick_write_path(const char *base, int overwrite, char *out, size_t out_len);

#endif
