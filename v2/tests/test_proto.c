#include "proto.h"
#include "compress.h"
#include "algo.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

static uint32_t test_seed(void) {
    uint32_t s = (uint32_t)time(NULL) ^ ((uint32_t)getpid() << 16) ^ (uint32_t)clock();
    return s ? s : 1;
}

static int test_compress(uint32_t *sd) {
    printf("test compress seed=%08x\n", *sd);
    int fails = 0;
    const char *names[] = {"none", "rle", "lz4"};

    uint8_t in[256];
    for (int i = 0; i < 256; i++) in[i] = (uint8_t)((*sd >> 8) & 0xFF);
    *sd ^= *sd << 13; *sd ^= *sd >> 17; *sd ^= *sd << 5;

    for (int mode = 0; mode < 3; mode++) {
        uint8_t cbuf[512], dbuf[512];
        int clen = compress_buf(mode, in, 256, cbuf, sizeof(cbuf));
        if (mode == 2 && clen < 0) {
            printf("  %-4s unavailable (no HAVE_LZ4), skip\n", names[mode]);
            continue;
        }
        if (clen < 0) { printf("  %-4s FAIL compress\n", names[mode]); fails++; continue; }
        int dlen = decompress_buf(mode, cbuf, (size_t)clen, dbuf, sizeof(dbuf));
        int ok = (dlen == 256) && (memcmp(dbuf, in, 256) == 0);
        printf("  %-4s in=256 out=%d ok=%d\n", names[mode], clen, ok);
        if (!ok) fails++;
    }
    printf("  seed_after=%08x\n", *sd);
    return fails;
}

static int test_negotiate_ok(uint32_t *sd) {
    printf("test negotiate ok seed=%08x\n", *sd);
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) { perror("socketpair"); return 1; }

    proto_params_t cli;
    proto_params_default(&cli);
    cli.kdf_mode = KDF_CUBE;
    cli.cipher_mode = CIPHER_KS16;
    cli.compress_mode = COMPRESS_RLE;

    proto_params_t srv;
    proto_params_default(&srv);
    srv.kdf_mode = KDF_CUBE;
    srv.cipher_mode = CIPHER_KS16;
    srv.compress_mode = COMPRESS_RLE;

    pid_t pid = fork();
    if (pid == 0) {
        close(sv[0]);
        proto_params_t out;
        int r = negotiate_server(sv[1], &out, &srv);
        _exit(r == 0 ? 0 : 1);
    }
    close(sv[1]);
    int r = negotiate_client(sv[0], &cli);
    int status = 0;
    waitpid(pid, &status, 0);
    close(sv[0]);
    int ok = (r == 0 && cli.kdf_mode == KDF_CUBE && cli.compress_mode == COMPRESS_RLE &&
              WIFEXITED(status) && WEXITSTATUS(status) == 0);
    printf("  client_r=%d kdf=%d compress=%d server_exit=%d ok=%d\n",
           r, cli.kdf_mode, cli.compress_mode,
           WIFEXITED(status) ? WEXITSTATUS(status) : -1, ok);
    *sd ^= *sd << 13; *sd ^= *sd >> 17; *sd ^= *sd << 5;
    return ok ? 0 : 1;
}

static int test_negotiate_mismatch(uint32_t *sd) {
    printf("test negotiate mismatch seed=%08x\n", *sd);
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) { perror("socketpair"); return 1; }

    proto_params_t cli;
    proto_params_default(&cli);
    cli.kdf_mode = KDF_BYTE;

    proto_params_t srv;
    proto_params_default(&srv);
    srv.kdf_mode = KDF_CUBE;

    pid_t pid = fork();
    if (pid == 0) {
        close(sv[0]);
        proto_params_t out;
        int r = negotiate_server(sv[1], &out, &srv);
        _exit(r == 0 ? 0 : 1);
    }
    close(sv[1]);
    int r = negotiate_client(sv[0], &cli);
    int status = 0;
    waitpid(pid, &status, 0);
    close(sv[0]);
    int ok = (r < 0) && WIFEXITED(status) && WEXITSTATUS(status) != 0;
    printf("  client_r=%d server_exit=%d ok=%d\n",
           r, WIFEXITED(status) ? WEXITSTATUS(status) : -1, ok);
    *sd ^= *sd << 13; *sd ^= *sd >> 17; *sd ^= *sd << 5;
    return ok ? 0 : 1;
}

static int test_packet_roundtrip(uint32_t *sd, int kdf, int cipher, int compress, const char *name) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) { perror("socketpair"); return 1; }

    algo_config_t cfg;
    algo_config_default(&cfg);
    cfg.kdf_mode = kdf;
    cfg.cipher_mode = cipher;
    cfg.compress_mode = compress;

    uint16_t S = (uint16_t)((*sd >> 8) & 0xFFFF);
    *sd ^= *sd << 13; *sd ^= *sd >> 17; *sd ^= *sd << 5;
    uint16_t tx = (uint16_t)((*sd >> 8) & 0xFFFF);
    *sd ^= *sd << 13; *sd ^= *sd >> 17; *sd ^= *sd << 5;
    uint16_t rx = tx;

    uint8_t payload[128];
    size_t plen = 1 + (*sd % 127);
    *sd ^= *sd << 13; *sd ^= *sd >> 17; *sd ^= *sd << 5;
    for (size_t i = 0; i < plen; i++) {
        payload[i] = (uint8_t)(*sd & 0xFF);
        *sd ^= *sd << 13; *sd ^= *sd >> 17; *sd ^= *sd << 5;
    }

    pid_t pid = fork();
    if (pid == 0) {
        close(sv[0]);
        if (send_packet(sv[1], payload, (uint16_t)plen, S, &tx, &cfg) < 0) _exit(2);
        _exit(0);
    }
    close(sv[1]);
    uint8_t out[MAX_PAYLOAD];
    uint16_t outlen = 0;
    int r = recv_packet(sv[0], out, &outlen, S, &rx, &cfg);
    int status = 0;
    waitpid(pid, &status, 0);
    close(sv[0]);

    int ok = (r == 0) && (outlen == plen) && (memcmp(out, payload, plen) == 0) &&
             WIFEXITED(status) && WEXITSTATUS(status) == 0;
    printf("  %-20s kdf=%d cipher=%d comp=%d len=%zu ok=%d\n",
           name, kdf, cipher, compress, plen, ok);
    return ok ? 0 : 1;
}

static int test_packet_roundtrips(uint32_t *sd) {
    printf("test packet roundtrips seed=%08x\n", *sd);
    int fails = 0;
    fails += test_packet_roundtrip(sd, KDF_CUBE, CIPHER_KS16, COMPRESS_NONE, "cube/ks16/none");
    fails += test_packet_roundtrip(sd, KDF_CUBE, CIPHER_RAW, COMPRESS_NONE, "cube/raw/none");
    fails += test_packet_roundtrip(sd, KDF_CUBE, CIPHER_BLOCK, COMPRESS_NONE, "cube/block/none");
    fails += test_packet_roundtrip(sd, KDF_BYTE, CIPHER_KS16, COMPRESS_NONE, "byte/ks16/none");
    fails += test_packet_roundtrip(sd, KDF_DOUBLE, CIPHER_KS16, COMPRESS_NONE, "double/ks16/none");

    fails += test_packet_roundtrip(sd, KDF_BYTE, CIPHER_KS16, COMPRESS_RLE, "byte/ks16/rle");
    fails += test_packet_roundtrip(sd, KDF_DOUBLE, CIPHER_KS16, COMPRESS_RLE, "double/ks16/rle");
    fails += test_packet_roundtrip(sd, KDF_CUBE, CIPHER_KS16, COMPRESS_RLE, "cube/ks16/rle");

    fails += test_packet_roundtrip(sd, KDF_BYTE, CIPHER_KS16, COMPRESS_LZ4, "byte/ks16/lz4");
    fails += test_packet_roundtrip(sd, KDF_DOUBLE, CIPHER_KS16, COMPRESS_LZ4, "double/ks16/lz4");
    fails += test_packet_roundtrip(sd, KDF_CUBE, CIPHER_KS16, COMPRESS_LZ4, "cube/ks16/lz4");

    printf("  seed_after=%08x\n", *sd);
    return fails;
}

int main(void) {
    if (algo_self_test() != 0) { fprintf(stderr, "self-test failed\n"); return 1; }
    uint32_t sd = test_seed();
    printf("tests: seed=%08x G=%u\n", sd, algo_g());
    int fails = 0;
    fails += test_compress(&sd);
    fails += test_negotiate_ok(&sd);
    fails += test_negotiate_mismatch(&sd);
    fails += test_packet_roundtrips(&sd);
    printf(fails ? "TESTS FAILED: %d\n" : "ALL TESTS OK\n", fails);
    return fails ? 1 : 0;
}
