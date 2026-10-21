#include "session.h"

#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

int session_open(session_t *s, const char *dir) {
    memset(s, 0, sizeof(*s));
    s->start = time(NULL);
    s->last_rx = s->start;
    s->last_tx = s->start;
    s->keepalive_interval = 30;
    s->keepalive_timeout = 90;
    const char *base = (dir && *dir) ? dir : ".";
    if (dir && *dir) {
        mkdir(dir, 0755);
        struct tm tm;
        localtime_r(&s->start, &tm);
        snprintf(s->path, sizeof(s->path),
                 "%s/session_%04d%02d%02d_%02d%02d%02d.log",
             base, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                 tm.tm_hour, tm.tm_min, tm.tm_sec);
    } else {
        snprintf(s->path, sizeof(s->path), "session.log");
    }
    s->log = fopen(s->path, "w");
    if (!s->log) {
        fprintf(stderr, "session: cannot open %s: %s\n", s->path, strerror(errno));
        return -1;
    }
    session_log(s, "session start path=%s", s->path);
    return 0;
}

void session_close(session_t *s) {
    if (s->log) {
        session_log(s, "session end rx=%llu tx=%llu",
                    (unsigned long long)s->packets_rx,
                    (unsigned long long)s->packets_tx);
        fclose(s->log);
        s->log = NULL;
    }
}

void session_log(session_t *s, const char *fmt, ...) {
    if (!s->log) return;
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    fprintf(s->log, "%02d:%02d:%02d ",
            tm.tm_hour, tm.tm_min, tm.tm_sec);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(s->log, fmt, ap);
    va_end(ap);
    fprintf(s->log, "\n");
    fflush(s->log);
}

void session_note_rx(session_t *s) {
    s->packets_rx++;
    s->last_rx = time(NULL);
}

void session_note_tx(session_t *s) {
    s->packets_tx++;
    s->last_tx = time(NULL);
}

int session_keepalive_due(session_t *s) {
    if (s->keepalive_interval <= 0) return 0;
    return (time(NULL) - s->last_tx) >= s->keepalive_interval;
}

int session_timed_out(session_t *s) {
    if (s->keepalive_timeout <= 0) return 0;
    return (time(NULL) - s->last_rx) >= s->keepalive_timeout;
}
