#include "mode_file/path_safe.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int file_exists(const char *path)
{
    return access(path, F_OK) == 0;
}

int pick_write_path(const char *base, int overwrite, char *out, size_t out_len)
{
    if (overwrite) {
        if (strlen(base) + 1 > out_len) return -1;
        strcpy(out, base);
        return 0;
    }
    if (!file_exists(base)) {
        if (strlen(base) + 1 > out_len) return -1;
        strcpy(out, base);
        return 0;
    }
    for (int i = 1; i <= 10000; i++) {
        if (snprintf(out, out_len, "%s.%d", base, i) >= (int)out_len) return -1;
        if (!file_exists(out)) return 0;
    }
    return -1;
}
