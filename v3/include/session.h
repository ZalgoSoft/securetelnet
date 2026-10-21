#ifndef SESSION_H
#define SESSION_H

#include <stdio.h>
#include <stdint.h>
#include <time.h>

typedef struct {
    FILE *log;
    char path[256];
    time_t start;
    time_t last_rx;
    time_t last_tx;
    uint64_t packets_rx;
    uint64_t packets_tx;
    uint16_t S;
    int keepalive_interval;
    int keepalive_timeout;
} session_t;

int session_open(session_t *s, const char *dir);
void session_close(session_t *s);
void session_log(session_t *s, const char *fmt, ...);
void session_note_rx(session_t *s);
void session_note_tx(session_t *s);
int session_keepalive_due(session_t *s);
int session_timed_out(session_t *s);

#endif
