#include "mode.h"
#include "proto.h"
#include "session.h"
#include "io.h"
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int relay(proto_ctx_t *p, session_t *s, int child_fd)
{
    for (;;) {
        fd_set rfds;
        int maxfd = p->fd > child_fd ? p->fd : child_fd;
        FD_ZERO(&rfds);
        FD_SET(p->fd, &rfds);
        FD_SET(child_fd, &rfds);
        if (select(maxfd + 1, &rfds, 0, 0, 0) < 0) return -1;
        if (FD_ISSET(p->fd, &rfds)) {
            uint8_t buf[65536];
            size_t len = sizeof(buf);
            if (proto_recv(p, buf, &len) != 0) return -1;
            session_note_rx(s);
            if (len > 0 && io_write_full(child_fd, buf, len) != (ssize_t)len) return -1;
        }
        if (FD_ISSET(child_fd, &rfds)) {
            uint8_t buf[4096];
            ssize_t n = read(child_fd, buf, sizeof(buf));
            if (n <= 0) return 0;
            if (proto_send(p, buf, (size_t)n) != 0) return -1;
            session_note_tx(s);
        }
    }
}

static int shell_server(proto_ctx_t *p, session_t *s, const mode_args_t *a)
{
    int sv[2];
    pid_t pid;
    int rc;
    session_log(s, "shell launch: %s", a->shell_path ? a->shell_path : "/bin/sh");
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -1;
    pid = fork();
    if (pid < 0) { close(sv[0]); close(sv[1]); return -1; }
    if (pid == 0) {
        close(sv[0]);
        dup2(sv[1], 0);
        dup2(sv[1], 1);
        dup2(sv[1], 2);
        close(sv[1]);
        execl(a->shell_path ? a->shell_path : "/bin/sh", "shell", (char *)0);
        _exit(127);
    }
    close(sv[1]);
    rc = relay(p, s, sv[0]);
    close(sv[0]);
    waitpid(pid, 0, 0);
    return rc;
}

static int shell_client(proto_ctx_t *p, session_t *s, const mode_args_t *a)
{
    (void)a;
    session_log(s, "shell client start");
    return relay(p, s, 0);
}

const mode_ops_t mode_shell_ops = {
    "shell",
    shell_server,
    shell_client
};
