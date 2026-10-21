#include "session.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

session_t *session_new(void)
{
    session_t *s = calloc(1, sizeof(*s));
    if (!s) return 0;
    s->keepalive_secs = 30;
    s->timeout_secs = 90;
    return s;
}

void session_free(session_t *s)
{
    if (!s) return;
    if (s->log) log_close(s->log);
    free(s);
}

int session_open_log(session_t *s, const char *dir, const char *prefix, int debug)
{
    if (!s) return -1;
    s->log = log_open(dir, prefix, debug);
    return s->log ? 0 : -1;
}

void session_set_secret(session_t *s, uint16_t secret)
{
    if (!s) return;
    s->secret = secret;
}

void session_note_tx(session_t *s)
{
    if (!s) return;
    s->tx_count++;
    s->last_tx = time(0);
}

void session_note_rx(session_t *s)
{
    if (!s) return;
    s->rx_count++;
    s->last_rx = time(0);
}

int session_keepalive_due(session_t *s, time_t now)
{
    if (!s) return 0;
    return (now - s->last_tx) >= s->keepalive_secs;
}

int session_timed_out(session_t *s, time_t now)
{
    if (!s) return 0;
    return (now - s->last_rx) >= s->timeout_secs;
}

void session_log(session_t *s, const char *fmt, ...)
{
    va_list ap;
    if (!s || !s->log) return;
    va_start(ap, fmt);
    log_vfmt(s->log, fmt, ap);
    va_end(ap);
}
