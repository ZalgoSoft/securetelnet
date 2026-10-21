#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

static void fmt_ts(char *buf, size_t n)
{
    time_t t = time(0);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(buf, n, "%Y-%m-%d %H:%M:%S", &tm);
}

static void write_line(log_t *l, const char *fmt, va_list ap)
{
    char ts[32];
    char body[1024];
    char line[1200];
    int n;
    if (!l || l->fd < 0) return;
    fmt_ts(ts, sizeof(ts));
    vsnprintf(body, sizeof(body), fmt, ap);
    n = snprintf(line, sizeof(line), "[%s] %s\n", ts, body);
    if (n > 0) {
        if (write(l->fd, line, (size_t)n) < 0) { }
        if (l->console && write(STDERR_FILENO, line, (size_t)n) < 0) { }
    }
}

log_t *log_open(const char *dir, const char *prefix, int debug)
{
    char path[1024];
    char ts[32];
    time_t t = time(0);
    struct tm tm;
    int fd;
    log_t *l;
    localtime_r(&t, &tm);
    strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", &tm);
    if (dir && *dir)
        snprintf(path, sizeof(path), "%s/%s_%s.log", dir, prefix, ts);
    else
        snprintf(path, sizeof(path), "./%s_%s.log", prefix, ts);
    fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return 0;
    l = calloc(1, sizeof(*l));
    if (!l) { close(fd); return 0; }
    l->fd = fd;
    l->debug = debug;
    l->console = debug; 
    return l;
}

void log_close(log_t *l)
{
    if (!l) return;
    if (l->fd >= 0) close(l->fd);
    free(l);
}

void log_set_debug(log_t *l, int on)
{
    if (l) l->debug = on;
}

void log_info(log_t *l, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    write_line(l, fmt, ap);
    va_end(ap);
}

void log_debug(log_t *l, const char *fmt, ...)
{
    va_list ap;
    if (!l || !l->debug) return;
    va_start(ap, fmt);
    write_line(l, fmt, ap);
    va_end(ap);
}

void log_hex(log_t *l, const char *label, const uint8_t *buf, size_t len)
{
    size_t i;
    char line[1024];
    size_t o = 0;
    if (!l || !l->debug) return;
    o += (size_t)snprintf(line + o, sizeof(line) - o, "%s ", label);
    for (i = 0; i < len && o + 3 < sizeof(line); i++)
        o += (size_t)snprintf(line + o, sizeof(line) - o, "%02x", buf[i]);
    log_debug(l, "%s", line);
}

void log_vfmt(log_t *l, const char *fmt, va_list ap)
{
    write_line(l, fmt, ap);
}
