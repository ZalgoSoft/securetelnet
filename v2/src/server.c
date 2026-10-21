#include "server.h"
#include "session.h"
#include "compress.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <signal.h>

#define MAX_KEYS 16

static int load_keys(const char *path, uint16_t *keys, int max) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int n = 0;
    unsigned int v;
    while (n < max && fscanf(f, "%x", &v) == 1) keys[n++] = (uint16_t)(v & 0xFFFF);
    fclose(f);
    return n;
}

static int load_pub(const char *path, uint16_t *pub) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    unsigned int v;
    int r = fscanf(f, "%x", &v);
    fclose(f);
    if (r != 1) return -1;
    *pub = (uint16_t)(v & 0xFFFF);
    return 0;
}

static int do_handshake(int fd, session_t *sess, uint32_t *seed,
                        const algo_config_t *cfg, uint16_t *S, uint16_t *ctr_tx,
                        uint16_t *ctr_rx) {
    uint32_t ctr32 = 0;
    if (dh_server_cfg(fd, S, &ctr32, seed, cfg) < 0) {
        session_log(sess, "dh failed");
        return -1;
    }
    session_log(sess, "dh ok S=%04x", *S);
    *ctr_tx = (uint16_t)ctr32;
    *ctr_rx = (uint16_t)ctr32;
    return 0;
}

static int do_negotiate(int fd, session_t *sess, const proto_params_t *caps,
                        proto_params_t *out) {
    if (negotiate_server(fd, out, caps) < 0) {
        session_log(sess, "negotiate failed");
        return -1;
    }
    session_log(sess, "negotiate ok kdf=%d cipher=%d compress=%d mac=%d",
                out->kdf_mode, out->cipher_mode, out->compress_mode, out->mac_mode);
    return 0;
}

static int do_auth(int fd, session_t *sess, const uint16_t *keys, int nkeys,
                   uint16_t S, uint32_t *seed, const algo_config_t *cfg) {
    int r;
    if (cfg->auth_mode == AUTH_HMAC)
        r = auth_hmac_server(fd, keys, nkeys, S, seed, cfg);
    else
        r = auth_schnorr_server(fd, keys, nkeys, S, seed, cfg);
    session_log(sess, "auth %s", r == 0 ? "OK" : "FAIL");
    return r;
}

static int mode_chat(int cfd, session_t *sess, uint16_t S,
                     uint16_t ctr_tx, uint16_t ctr_rx, const algo_config_t *cfg) {
    fd_set rfds;
    char line[512];
    uint8_t in[1024];
    uint16_t inlen;
    printf("server> "); fflush(stdout);
    for (;;) {
        if (session_timed_out(sess)) { session_log(sess, "timeout"); break; }
        FD_ZERO(&rfds);
        FD_SET(cfd, &rfds);
        FD_SET(STDIN_FILENO, &rfds);
        int maxfd = cfd > STDIN_FILENO ? cfd : STDIN_FILENO;
        struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
        int rv = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (rv < 0) { perror("select"); break; }
        if (rv == 0) {
            if (session_keepalive_due(sess)) {
                if (send_packet(cfd, (const uint8_t*)"", 0, S, &ctr_tx, cfg) < 0) break;
                session_note_tx(sess);
            }
            continue;
        }
        if (FD_ISSET(cfd, &rfds)) {
            if (recv_packet(cfd, in, &inlen, S, &ctr_rx, cfg) < 0) break;
            session_note_rx(sess);
            if (inlen == 0) continue;
            in[inlen] = 0;
            printf("\rclient> %s\nserver> ", in);
            fflush(stdout);
        }
        if (FD_ISSET(STDIN_FILENO, &rfds)) {
            if (!fgets(line, sizeof(line), stdin)) break;
            size_t n = strlen(line);
            if (n && line[n - 1] == '\n') line[--n] = 0;
            if (send_packet(cfd, (uint8_t*)line, (uint16_t)n, S, &ctr_tx, cfg) < 0) break;
            session_note_tx(sess);
            printf("server> "); fflush(stdout);
        }
    }
    return 0;
}

static int mode_shell(int cfd, session_t *sess, uint16_t S,
                      uint16_t ctr_tx, uint16_t ctr_rx, const algo_config_t *cfg,
                      const char *shell) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) { perror("socketpair"); return -1; }
    pid_t pid = fork();
    if (pid == 0) {
        close(sv[0]);
        close(cfd);
        dup2(sv[1], STDIN_FILENO);
        dup2(sv[1], STDOUT_FILENO);
        dup2(sv[1], STDERR_FILENO);
        close(sv[1]);
        execl(shell, shell, (char*)NULL);
        _exit(127);
    }
    close(sv[1]);
    session_log(sess, "shell pid=%d path=%s", (int)pid, shell);

    fd_set rfds;
    uint8_t in[1024];
    uint16_t inlen;
    char outbuf[1024];
    for (;;) {
        if (session_timed_out(sess)) break;
        FD_ZERO(&rfds);
        FD_SET(cfd, &rfds);
        FD_SET(sv[0], &rfds);
        int maxfd = cfd > sv[0] ? cfd : sv[0];
        struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
        int rv = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (rv < 0) break;
        if (rv == 0) {
            int st;
            if (waitpid(pid, &st, WNOHANG) == pid) { session_log(sess, "shell exit %d", WEXITSTATUS(st)); break; }
            if (session_keepalive_due(sess)) {
                if (send_packet(cfd, (const uint8_t*)"", 0, S, &ctr_tx, cfg) < 0) break;
                session_note_tx(sess);
            }
            continue;
        }
        if (FD_ISSET(sv[0], &rfds)) {
            ssize_t n = read(sv[0], outbuf, sizeof(outbuf));
            if (n <= 0) break;
            if (send_packet(cfd, (uint8_t*)outbuf, (uint16_t)n, S, &ctr_tx, cfg) < 0) break;
            session_note_tx(sess);
        }
        if (FD_ISSET(cfd, &rfds)) {
            if (recv_packet(cfd, in, &inlen, S, &ctr_rx, cfg) < 0) break;
            session_note_rx(sess);
            if (inlen == 0) continue;
            if (write_full(sv[0], in, inlen) < 0) break;
        }
    }
    close(sv[0]);
    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);
    return 0;
}

static int mode_file(int cfd, session_t *sess, uint16_t S,
                     uint16_t ctr_tx, uint16_t ctr_rx, const algo_config_t *cfg) {
    uint8_t in[MAX_PAYLOAD];
    uint16_t inlen;
    for (;;) {
        if (session_timed_out(sess)) break;
        if (recv_packet(cfd, in, &inlen, S, &ctr_rx, cfg) < 0) break;
        session_note_rx(sess);
        if (inlen == 0) continue;
        in[inlen] = 0;
        char *cmd = (char*)in;
        if (!strncmp(cmd, "put ", 4)) {
            const char *path = cmd + 4;
            uint8_t hdr[2];
            if (recv_packet(cfd, hdr, &inlen, S, &ctr_rx, cfg) < 0) break;
            uint16_t flen = (uint16_t)(hdr[0] | (hdr[1] << 8));
            FILE *f = fopen(path, "wb");
            if (!f) {
                uint8_t nok = 'N';
                send_packet(cfd, &nok, 1, S, &ctr_tx, cfg);
                session_note_tx(sess);
                continue;
            }
            uint16_t got = 0;
            while (got < flen) {
                if (recv_packet(cfd, in, &inlen, S, &ctr_rx, cfg) < 0) { fclose(f); return -1; }
                session_note_rx(sess);
                fwrite(in, 1, inlen, f);
                got += inlen;
            }
            fclose(f);
            uint8_t ok = 'O';
            send_packet(cfd, &ok, 1, S, &ctr_tx, cfg);
            session_note_tx(sess);
            session_log(sess, "file put %s len=%u", path, flen);
        } else if (!strncmp(cmd, "get ", 4)) {
            const char *path = cmd + 4;
            FILE *f = fopen(path, "rb");
            if (!f) {
                uint8_t nok = 'N';
                send_packet(cfd, &nok, 1, S, &ctr_tx, cfg);
                session_note_tx(sess);
                continue;
            }
            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            fseek(f, 0, SEEK_SET);
            if (sz < 0 || sz > 0xFFFF) { fclose(f); uint8_t nok = 'N'; send_packet(cfd, &nok, 1, S, &ctr_tx, cfg); continue; }
            uint16_t flen = (uint16_t)sz;
            uint8_t hdr[2] = { flen & 0xFF, flen >> 8 };
            send_packet(cfd, hdr, 2, S, &ctr_tx, cfg);
            session_note_tx(sess);
            uint8_t buf[1024];
            size_t r;
            while ((r = fread(buf, 1, sizeof(buf), f)) > 0) {
                send_packet(cfd, buf, (uint16_t)r, S, &ctr_tx, cfg);
                session_note_tx(sess);
            }
            fclose(f);
            session_log(sess, "file get %s len=%u", path, flen);
        } else if (!strcmp(cmd, "quit")) {
            break;
        }
    }
    return 0;
}

int server_run_stub(int port, const char *keyfile, int mode, const char *shell,
               const proto_params_t *caps, const char *session_dir) {
    uint16_t keys[MAX_KEYS];
    int nkeys = load_keys(keyfile, keys, MAX_KEYS);
    if (nkeys == 0) { fprintf(stderr, "no keys in %s\n", keyfile); return 1; }

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);
    if (bind(sfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(sfd, 1) < 0) { perror("listen"); return 1; }
    printf("server: listening on %d, %d key(s), mode=%d\n", port, nkeys, mode);

    int cfd = accept(sfd, NULL, NULL);
    if (cfd < 0) { perror("accept"); return 1; }
    printf("server: client connected\n");

    session_t sess;
    if (session_open(&sess, session_dir) < 0) return 1;

    uint32_t seed = (uint32_t)time(NULL) ^ ((uint32_t)getpid() << 16) ^ (uint32_t)clock();
    uint16_t S = 0;
    uint16_t ctr_tx = 0, ctr_rx = 0;

    if (do_negotiate(cfd, &sess, caps, &(proto_params_t){0}) < 0) { session_close(&sess); return 1; }

    proto_params_t negotiated;
    lseek(cfd, 0, SEEK_SET);
    close(cfd);
    close(sfd);
    session_close(&sess);
    return 0;
}

int server_run_real(int port, const char *keyfile, int mode, const char *shell, // server_run_real
                    const proto_params_t *caps, const char *session_dir) {
    uint16_t keys[MAX_KEYS];
    int nkeys = load_keys(keyfile, keys, MAX_KEYS);
    if (nkeys == 0) { fprintf(stderr, "no keys in %s\n", keyfile); return 1; }

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);
    if (bind(sfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(sfd, 1) < 0) { perror("listen"); return 1; }
    printf("server: listening on %d, %d key(s), mode=%d\n", port, nkeys, mode);

    int cfd = accept(sfd, NULL, NULL);
    if (cfd < 0) { perror("accept"); return 1; }
    printf("server: client connected\n");

    session_t sess;
    if (session_open(&sess, session_dir) < 0) return 1;

    proto_params_t negotiated;
    if (do_negotiate(cfd, &sess, caps, &negotiated) < 0) { close(cfd); close(sfd); session_close(&sess); return 1; }

    algo_config_t cfg;
    algo_from_proto_params(&cfg, &negotiated);

    uint32_t seed = (uint32_t)time(NULL) ^ ((uint32_t)getpid() << 16) ^ (uint32_t)clock();
    uint16_t S = 0, ctr_tx = 0, ctr_rx = 0;
    if (do_handshake(cfd, &sess, &seed, &cfg, &S, &ctr_tx, &ctr_rx) < 0) { close(cfd); close(sfd); session_close(&sess); return 1; }
    sess.S = S;

    if (do_auth(cfd, &sess, keys, nkeys, S, &seed, &cfg) < 0) { close(cfd); close(sfd); session_close(&sess); return 1; }
    printf("server: auth OK, S=%u\n", S);

    int r = 0;
    if (mode == MODE_CHAT) r = mode_chat(cfd, &sess, S, ctr_tx, ctr_rx, &cfg);
    else if (mode == MODE_SHELL) r = mode_shell(cfd, &sess, S, ctr_tx, ctr_rx, &cfg, shell);
    else if (mode == MODE_FILE) r = mode_file(cfd, &sess, S, ctr_tx, ctr_rx, &cfg);

    close(cfd);
    close(sfd);
    session_close(&sess);
    return r;
}

int server_run(int port, const char *keyfile, int mode, const char *shell,
               const proto_params_t *caps, const char *session_dir) {
    return server_run_real(port, keyfile, mode, shell, caps, session_dir);
}
