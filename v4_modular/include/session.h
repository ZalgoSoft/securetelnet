#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>
#include <time.h>

typedef struct log_t log_t;

typedef struct session_t {
    log_t *log;
    uint16_t secret;
    uint16_t tx_count;
    uint16_t rx_count;
    int keepalive_secs;
    int timeout_secs;
    time_t last_tx;
    time_t last_rx;
} session_t;

session_t *session_new(void);
void session_free(session_t *s);
int session_open_log(session_t *s, const char *dir, const char *prefix, int debug);
void session_set_secret(session_t *s, uint16_t secret);
void session_note_tx(session_t *s);
void session_note_rx(session_t *s);
int session_keepalive_due(session_t *s, time_t now);
int session_timed_out(session_t *s, time_t now);
void session_log(session_t *s, const char *fmt, ...);

#endif
