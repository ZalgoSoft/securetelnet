#include "mode_file/path_safe.h"
#include <stdio.h>

int main(void)
{
    char out[256];
    printf("safe('a/b'): %d\n", path_is_safe("a/b"));
    printf("safe('/x'): %d\n", path_is_safe("/x"));
    printf("safe('../x'): %d\n", path_is_safe("../x"));
    printf("safe('a/../b'): %d\n", path_is_safe("a/../b"));
    printf("pick(overwrite=1): %d -> %s\n", pick_write_path("foo.txt", 1, out, sizeof(out)), out);
    printf("pick(overwrite=0): %d -> %s\n", pick_write_path("foo.txt", 0, out, sizeof(out)), out);
    return 0;
}
