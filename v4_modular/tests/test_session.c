#include "session.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    session_t *s = session_new();
    time_t t0 = 1000;
    s->last_tx = t0;
    s->last_rx = t0;
    printf("keepalive at t0+29: %d\n", session_keepalive_due(s, t0 + 29));
    printf("keepalive at t0+30: %d\n", session_keepalive_due(s, t0 + 30));
    printf("timeout at t0+89: %d\n", session_timed_out(s, t0 + 89));
    printf("timeout at t0+90: %d\n", session_timed_out(s, t0 + 90));
    session_free(s);
    return 0;
}
