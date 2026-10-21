#include "mode_file/path_safe.h"
#include <string.h>

int path_is_safe(const char *path)
{
    const char *p;
    if (!path || !*path) return 0;
    if (path[0] == '/') return 0;
    p = path;
    while (*p) {
        const char *seg = p;
        while (*p && *p != '/') p++;
        if (p - seg == 2 && seg[0] == '.' && seg[1] == '.') return 0;
        if (*p == '/') p++;
    }
    return 1;
}
