#include "io.h"
#include <unistd.h>
#include <errno.h>

ssize_t io_read_full(int fd, void *buf, size_t n)
{
    size_t got = 0;
    char *p = buf;
    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r == 0) return (ssize_t)got;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        got += (size_t)r;
    }
    return (ssize_t)got;
}

ssize_t io_write_full(int fd, const void *buf, size_t n)
{
    size_t sent = 0;
    const char *p = buf;
    while (sent < n) {
        ssize_t w = write(fd, p + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)w;
    }
    return (ssize_t)sent;
}
