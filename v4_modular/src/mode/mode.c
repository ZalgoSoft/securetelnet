#include "mode.h"
#include <string.h>

static const mode_ops_t *mode_list[] = {
    &mode_chat_ops,
    &mode_shell_ops,
    &mode_file_ops
};

#define MODE_COUNT (sizeof(mode_list)/sizeof(mode_list[0]))

const mode_ops_t *mode_find(const char *name)
{
    size_t i;
    for (i = 0; i < MODE_COUNT; i++)
        if (strcmp(mode_list[i]->name, name) == 0)
            return mode_list[i];
    return 0;
}

const mode_ops_t *mode_first(void) { return mode_list[0]; }

const mode_ops_t *mode_next(const mode_ops_t *cur)
{
    size_t i;
    for (i = 0; i < MODE_COUNT; i++)
        if (mode_list[i] == cur && i + 1 < MODE_COUNT)
            return mode_list[i + 1];
    return 0;
}
