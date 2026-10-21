#ifndef IO_H
#define IO_H

#include <stddef.h>
#include <unistd.h>

ssize_t io_read_full(int fd, void *buf, size_t n);
ssize_t io_write_full(int fd, const void *buf, size_t n);

#endif
