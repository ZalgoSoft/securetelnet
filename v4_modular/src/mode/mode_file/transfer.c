#include "mode_file/transfer.h"
#include "mode_file/path_safe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

static int write_all(int fd, const uint8_t *buf, size_t n)
{
    while (n) {
        ssize_t w = write(fd, buf, n);
        if (w <= 0) return -1;
        buf += w;
        n -= (size_t)w;
    }
    return 0;
}

int serve_file(proto_ctx_t *p, session_t *s, int overwrite)
{
    uint8_t buf[65536];
    size_t len = sizeof(buf);
    char target[4096];
    char chosen[4096];
    int out_fd = -1;
    uint8_t cmd_buf[8];
    size_t cmd_len = sizeof(cmd_buf);
    uint32_t total, remaining;

    if (proto_recv(p, cmd_buf, &cmd_len) != 0) return -1;
    session_note_rx(s);
    if (cmd_len != 3 || memcmp(cmd_buf, "put", 3) != 0) {
        if (proto_send(p, (const uint8_t *)"NK", 2) != 0) return -1;
        session_note_tx(s);
        return -1;
    }

    len = 4;
    if (proto_recv(p, buf, &len) != 0) return -1;
    session_note_rx(s);
    if (len != 4) return -1;
    total = (uint32_t)buf[0]
          | ((uint32_t)buf[1] <<  8)
          | ((uint32_t)buf[2] << 16)
          | ((uint32_t)buf[3] << 24);

    {
        uint8_t path_buf[4096];
        size_t plen = sizeof(path_buf);
        if (proto_recv(p, path_buf, &plen) != 0) return -1;
        session_note_rx(s);
        if (plen == 0 || plen >= sizeof(target)) return -1;
        memcpy(target, path_buf, plen);
        target[plen] = 0;
    }
    if (!path_is_safe(target)) return -1;
    if (pick_write_path(target, overwrite, chosen, sizeof(chosen)) != 0) return -1;
    out_fd = open(chosen, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) return -1;

    remaining = total;
    while (remaining > 0) {
        size_t chunk = remaining < 1024 ? remaining : 1024;
        len = chunk;
        if (proto_recv(p, buf, &len) != 0) { close(out_fd); return -1; }
        session_note_rx(s);
        if (len == 0) break;
        if (write_all(out_fd, buf, len) != 0) { close(out_fd); return -1; }
        remaining -= (uint32_t)len;
    }
    close(out_fd);
    session_log(s, "file received: %s (%u bytes)", chosen, total);

    if (proto_send(p, (const uint8_t *)"OK", 2) != 0) return -1;
    session_note_tx(s);
    return 0;
}

int do_put(proto_ctx_t *p, session_t *s, const char *local, const char *remote)
{
    uint8_t buf[1024];
    int fd;
    off_t size;
    ssize_t n;
    session_log(s, "put %s -> %s", local, remote);
    fd = open(local, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "cannot open %s\n", local); return -1; }
    size = lseek(fd, 0, SEEK_END);
    if (size < 0) { close(fd); return -1; }
    if (size > 0xFFFFFFFFu) { fprintf(stderr, "file too large\n"); close(fd); return -1; }
    lseek(fd, 0, SEEK_SET);
    if (proto_send(p, (const uint8_t *)"put", 3) != 0) { close(fd); return -1; }
    session_note_tx(s);
    buf[0] = (uint8_t)((size >>  0) & 0xFF);
    buf[1] = (uint8_t)((size >>  8) & 0xFF);
    buf[2] = (uint8_t)((size >> 16) & 0xFF);
    buf[3] = (uint8_t)((size >> 24) & 0xFF);
    if (proto_send(p, buf, 4) != 0) { close(fd); return -1; }
    session_note_tx(s);
    if (proto_send(p, (const uint8_t *)remote, strlen(remote)) != 0) { close(fd); return -1; }
    session_note_tx(s);
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        if (proto_send(p, buf, (size_t)n) != 0) { close(fd); return -1; }
        session_note_tx(s);
    }
    close(fd);
    {
        size_t len = 2;
        if (proto_recv(p, buf, &len) != 0) return -1;
        session_note_rx(s);
        if (len < 1 || buf[0] != 'O') { fprintf(stderr, "peer rejected file\n"); return -1; }
    }
    return 0;
}
int do_get(proto_ctx_t *p, session_t *s, const char *remote, const char *local)
{
    uint8_t buf[1024];
    char chosen[4096];
    int fd;
    size_t len;
    session_log(s, "get %s -> %s", remote, local);
    if (proto_send(p, (const uint8_t *)"get", 3) != 0) return -1;
    session_note_tx(s);
    if (proto_send(p, (const uint8_t *)remote, strlen(remote)) != 0) return -1;
    session_note_tx(s);
    len = 2;
    if (proto_recv(p, buf, &len) != 0) return -1;
    session_note_rx(s);
    if (len < 1 || buf[0] != 'O') { fprintf(stderr, "remote open failed\n"); return -1; }
    if (pick_write_path(local, 0, chosen, sizeof(chosen)) != 0) return -1;
    fd = open(chosen, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    for (;;) {
        len = sizeof(buf);
        if (proto_recv(p, buf, &len) != 0) { close(fd); return -1; }
        session_note_rx(s);
        if (len == 0) break;
        if (write_all(fd, buf, len) != 0) { close(fd); return -1; }
    }
    close(fd);
    session_log(s, "file written: %s", chosen);
    return 0;
}
