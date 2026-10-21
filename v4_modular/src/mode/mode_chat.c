#include "mode.h"
#include "proto.h"
#include "session.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>

static int chat_loop(proto_ctx_t *p, session_t *s, const char *prompt)
{
    for (;;) {
        fd_set rfds;
        int maxfd;
        FD_ZERO(&rfds);
        FD_SET(0, &rfds);
        FD_SET(p->fd, &rfds);
        maxfd = p->fd > 0 ? p->fd : 0;
        if (select(maxfd + 1, &rfds, 0, 0, 0) < 0) return -1;
        if (FD_ISSET(0, &rfds)) {
            char line[4096];
            ssize_t n = read(0, line, sizeof(line) - 1);
            if (n <= 0) return 0;
            while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) n--;
            if (proto_send(p, (uint8_t *)line, (size_t)n) != 0) return -1;
            session_note_tx(s);
        }
        if (FD_ISSET(p->fd, &rfds)) {
            uint8_t buf[65536];
            size_t len = sizeof(buf);
            if (proto_recv(p, buf, &len) != 0) return -1;
            session_note_rx(s);
            if (len > 0) {
                if (write(1, "\rpeer: ", 6) < 0) { }
                if (write(1, buf, len) < 0) { }
                if (write(1, "\n", 1) < 0) { }
                if (write(1, prompt, strlen(prompt)) < 0) { }
            }
        }
    }
}

static int chat_server(proto_ctx_t *p, session_t *s, const mode_args_t *a)
{
    (void)a;
    session_log(s, "chat server start");
    if (write(1, "server> ", 8) < 0) { }
    return chat_loop(p, s, "server> ");
}

static int chat_client(proto_ctx_t *p, session_t *s, const mode_args_t *a)
{
    (void)a;
    session_log(s, "chat client start");
    if (write(1, "client> ", 8) < 0) { }
    return chat_loop(p, s, "client> ");
}

const mode_ops_t mode_chat_ops = {
    "chat",
    chat_server,
    chat_client
};
