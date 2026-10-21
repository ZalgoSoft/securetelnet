#ifndef LOG_H
#define LOG_H

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

typedef struct log_t {
    int fd;
    int debug;
    int console;
} log_t;

log_t *log_open(const char *dir, const char *prefix, int debug);
void log_close(log_t *l);
void log_set_debug(log_t *l, int on);
void log_info(log_t *l, const char *fmt, ...);
void log_debug(log_t *l, const char *fmt, ...);
void log_hex(log_t *l, const char *label, const uint8_t *buf, size_t len);
void log_vfmt(log_t *l, const char *fmt, va_list ap);

#endif
