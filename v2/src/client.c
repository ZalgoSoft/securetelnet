#include "client.h"
#include "session.h"
#include "compress.h"
#include "server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int load_priv(const char *path, uint16_t *priv) {
    FILE *f = fopen(path, "r");
    if (!f) { perror("fopen priv"); return -1; }
    unsigned int v;
    int r = fscanf(f, "%x", &v);
    fclose(f);
    if (r != 1) return -1;
    *priv = (uint16_t)(v & 0xFFFF);
    return 0;
}

static int mode_chat(int fd, session_t *sess, uint16_t S,
                     uint16_t ctr_tx, uint16_t ctr_rx, const algo_config_t *cfg) {
    fd_set rfds;
    char line[512];
    uint8_t in[1024];
    uint16_t inlen;
    printf("client> "); fflush(stdout);
    for (;;) {
        if (session_timed_out(sess)) break;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        FD_SET(STDIN_FILENO, &rfds);
        int maxfd = fd > STDIN_FILENO ? fd : STDIN_FILENO;
        struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
        int rv = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (rv < 0) break;
        if (rv == 0) {
            if (session_keepalive_due(sess)) {
                if (send_packet(fd, (const uint8_t*)"", 0, S, &ctr_tx, cfg) < 0) break;
                session_note_tx(sess);
            }
            continue;
        }
        if (FD_ISSET(fd, &rfds)) {
            if (recv_packet(fd, in, &inlen, S, &ctr_rx, cfg) < 0) break;
            session_note_rx(sess);
            if (inlen == 0) continue;
            in[inlen] = 0;
            printf("\rserver> %s\nclient> ", in);
            fflush(stdout);
        }
        if (FD_ISSET(STDIN_FILENO, &rfds)) {
            if (!fgets(line, sizeof(line), stdin)) break;
            size_t n = strlen(line);
            if (n && line[n - 1] == '\n') line[--n] = 0;
            if (send_packet(fd, (uint8_t*)line, (uint16_t)n, S, &ctr_tx, cfg) < 0) break;
            session_note_tx(sess);
            printf("client> "); fflush(stdout);
        }
    }
    return 0;
}

static int mode_shell(int fd, session_t *sess, uint16_t S,
                      uint16_t ctr_tx, uint16_t ctr_rx, const algo_config_t *cfg) {
    fd_set rfds;
    uint8_t in[1024];
    uint16_t inlen;
    char outbuf[1024];
    for (;;) {
        if (session_timed_out(sess)) break;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        FD_SET(STDIN_FILENO, &rfds);
        int maxfd = fd > STDIN_FILENO ? fd : STDIN_FILENO;
        struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
        int rv = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (rv < 0) break;
        if (rv == 0) {
            if (session_keepalive_due(sess)) {
                if (send_packet(fd, (const uint8_t*)"", 0, S, &ctr_tx, cfg) < 0) break;
                session_note_tx(sess);
            }
            continue;
        }
        if (FD_ISSET(fd, &rfds)) {
            if (recv_packet(fd, in, &inlen, S, &ctr_rx, cfg) < 0) break;
            session_note_rx(sess);
            if (inlen == 0) continue;
            ssize_t w = write(STDOUT_FILENO, in, inlen);
            (void)w;
        }
        if (FD_ISSET(STDIN_FILENO, &rfds)) {
            ssize_t n = read(STDIN_FILENO, outbuf, sizeof(outbuf));
            if (n <= 0) break;
            if (send_packet(fd, (uint8_t*)outbuf, (uint16_t)n, S, &ctr_tx, cfg) < 0) break;
            session_note_tx(sess);
        }
    }
    return 0;
}

static int mode_file(int fd, session_t *sess, uint16_t S,
                     uint16_t ctr_tx, uint16_t ctr_rx, const algo_config_t *cfg,
                     const char *file_cmd) {
    uint8_t in[MAX_PAYLOAD];
    uint16_t inlen;

    if (!strncmp(file_cmd, "get ", 4)) {
        if (send_packet(fd, (const uint8_t*)file_cmd, (uint16_t)strlen(file_cmd), S, &ctr_tx, cfg) < 0) return 1;
        session_note_tx(sess);
        if (recv_packet(fd, in, &inlen, S, &ctr_rx, cfg) < 0) return 1;
        session_note_rx(sess);
        if (inlen == 1 && in[0] == 'N') { fprintf(stderr, "server: no such file\n"); return 1; }
        uint16_t flen = (uint16_t)(in[0] | (in[1] << 8));
        const char *path = file_cmd + 4;
        FILE *f = fopen(path, "wb");
        if (!f) { perror("fopen"); return 1; }
        uint16_t got = 0;
        while (got < flen) {
            if (recv_packet(fd, in, &inlen, S, &ctr_rx, cfg) < 0) { fclose(f); return 1; }
            session_note_rx(sess);
            fwrite(in, 1, inlen, f);
            got += inlen;
        }
        fclose(f);
        printf("saved %s (%u bytes)\n", path, flen);
        return 0;
    }
    if (!strncmp(file_cmd, "put ", 4)) {
        const char *path = file_cmd + 4;
        FILE *f = fopen(path, "rb");
        if (!f) { perror("fopen"); return 1; }
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (sz < 0 || sz > 0xFFFF) { fclose(f); fprintf(stderr, "file too large\n"); return 1; }
        uint16_t flen = (uint16_t)sz;
        if (send_packet(fd, (const uint8_t*)file_cmd, (uint16_t)strlen(file_cmd), S, &ctr_tx, cfg) < 0) { fclose(f); return 1; }
        session_note_tx(sess);
        uint8_t hdr[2] = { flen & 0xFF, flen >> 8 };
        if (send_packet(fd, hdr, 2, S, &ctr_tx, cfg) < 0) { fclose(f); return 1; }
        session_note_tx(sess);
        uint8_t buf[1024];
        size_t r;
        while ((r = fread(buf, 1, sizeof(buf), f)) > 0) {
            if (send_packet(fd, buf, (uint16_t)r, S, &ctr_tx, cfg) < 0) { fclose(f); return 1; }
            session_note_tx(sess);
        }
        fclose(f);
        if (recv_packet(fd, in, &inlen, S, &ctr_rx, cfg) < 0) return 1;
        session_note_rx(sess);
        if (inlen == 1 && in[0] == 'O') printf("sent %s (%u bytes)\n", path, flen);
        else fprintf(stderr, "server rejected\n");
        return 0;
    }
    fprintf(stderr, "unknown file cmd: %s\n", file_cmd);
    return 1;
}

int client_run(const char *host, int port, const char *privfile, int mode,
               const char *shell, const proto_params_t *caps, const char *session_dir,
               const char *file_cmd) {
    uint16_t priv;
    if (load_priv(privfile, &priv) < 0) return 1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) { fprintf(stderr, "bad host\n"); return 1; }
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("connect"); return 1; }

    session_t sess;
    if (session_open(&sess, session_dir) < 0) return 1;

    proto_params_t negotiated = *caps;
    if (negotiate_client(fd, &negotiated) < 0) { fprintf(stderr, "negotiate failed\n"); close(fd); session_close(&sess); return 1; }
    algo_config_t cfg;
    algo_from_proto_params(&cfg, &negotiated);

    uint32_t seed = (uint32_t)time(NULL) ^ ((uint32_t)getpid() << 16) ^ (uint32_t)clock();
    uint16_t S = 0, ctr_tx = 0, ctr_rx = 0;
    uint32_t ctr32 = 0;
    if (dh_client_cfg(fd, &S, &ctr32, &seed, &cfg) < 0) { fprintf(stderr, "dh failed\n"); close(fd); session_close(&sess); return 1; }
    ctr_tx = (uint16_t)ctr32; ctr_rx = (uint16_t)ctr32;
    sess.S = S;

    int ar;
    if (cfg.auth_mode == AUTH_HMAC) ar = auth_hmac_client(fd, priv, S, &cfg);
    else ar = auth_schnorr_client(fd, priv, &seed, &cfg);
    if (ar < 0) { fprintf(stderr, "auth failed\n"); close(fd); session_close(&sess); return 1; }
    printf("client: auth OK, S=%u\n", S);
    session_log(&sess, "auth OK S=%04x", S);

    int r = 0;
    if (mode == MODE_CHAT) r = mode_chat(fd, &sess, S, ctr_tx, ctr_rx, &cfg);
    else if (mode == MODE_SHELL) r = mode_shell(fd, &sess, S, ctr_tx, ctr_rx, &cfg);
    else if (mode == MODE_FILE) r = mode_file(fd, &sess, S, ctr_tx, ctr_rx, &cfg, file_cmd);

    close(fd);
    session_close(&sess);
    return r;
}
