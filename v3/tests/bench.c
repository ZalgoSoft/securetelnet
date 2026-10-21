#include "algo.h"
#include "proto.h"
#include "compress.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static uint32_t bench_seed(void) {
    uint32_t s = (uint32_t)time(NULL) ^ ((uint32_t)getpid() << 16) ^ (uint32_t)clock();
    return s ? s : 1;
}

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void bench_modpow(uint32_t *sd, int n) {
    algo_config_t cfg; algo_config_default(&cfg);
    uint16_t G = algo_g();
    double t0 = now_s();
    for (int i = 0; i < n; i++) {
        uint16_t a = (uint16_t)(1 + (prng_next(sd, &cfg) % (P - 2)));
        modpow(G, a);
    }
    double dt = now_s() - t0;
    printf("modpow           n=%-7d %.3fs  %10.1f ops/s  %8.2f us/op\n",
           n, dt, n / dt, dt / n * 1e6);
}

static void bench_ks16(uint32_t *sd, int n) {
    algo_config_t cfg; algo_config_default(&cfg);
    double t0 = now_s();
    uint32_t acc = 0;
    for (int i = 0; i < n; i++) {
        uint16_t S = (uint16_t)(prng_next(sd, &cfg) & 0xFFFF);
        acc += ks16_cfg(S, (uint16_t)i, cfg.kdf_mode);
    }
    double dt = now_s() - t0;
    printf("ks16 (cube)      n=%-7d %.3fs  %10.1f ops/s  %8.2f us/op  acc=%u\n",
           n, dt, n / dt, dt / n * 1e6, acc & 0xFFFF);
}

static void bench_stream_xor(uint32_t *sd, int n, int len, int mode, const char *name) {
    algo_config_t cfg; algo_config_default(&cfg);
    cfg.cipher_mode = mode;
    uint8_t buf[1024];
    uint16_t S = (uint16_t)(prng_next(sd, &cfg) & 0xFFFF);
    for (int i = 0; i < len; i++) buf[i] = (uint8_t)i;
    double t0 = now_s();
    for (int i = 0; i < n; i++)
        stream_xor_cfg(buf, (size_t)len, S, (uint16_t)i, &cfg);
    double dt = now_s() - t0;
    double mbps = (double)n * len * 8.0 / dt / 1e6;
    printf("stream_xor %-6s len=%-5d n=%-7d %.3fs  %10.1f pkt/s  %8.2f Mbps\n",
           name, len, n, dt, n / dt, mbps);
}

static void bench_schnorr(uint32_t *sd, int n) {
    algo_config_t cfg; algo_config_default(&cfg);
    uint16_t G = algo_g();
    double t0 = now_s();
    int ok = 0;
    for (int i = 0; i < n; i++) {
        uint16_t priv = (uint16_t)(1 + (prng_next(sd, &cfg) % (P - 2)));
        uint16_t pub = modpow(G, priv);
        uint16_t c = (uint16_t)(prng_next(sd, &cfg) & 0xFFFF);
        uint16_t R, s;
        schnorr_prove_cfg(priv, c, &R, &s, sd, &cfg);
        if (schnorr_verify_cfg(pub, c, R, s, &cfg)) ok++;
    }
    double dt = now_s() - t0;
    printf("schnorr prove+ver n=%-7d %.3fs  %10.1f ops/s  %8.2f us/op  ok=%d\n",
           n, dt, n / dt, dt / n * 1e6, ok);
}

static void bench_schnorr_cache(uint32_t *sd, int n) {
    algo_config_t cfg; algo_config_default(&cfg);
    cfg.schnorr_cache = 1;
    uint16_t G = algo_g();
    uint16_t priv = (uint16_t)(1 + (prng_next(sd, &cfg) % (P - 2)));
    uint16_t pub = modpow(G, priv);
    double t0 = now_s();
    int ok = 0;
    for (int i = 0; i < n; i++) {
        uint16_t c = (uint16_t)(prng_next(sd, &cfg) & 0xFF);
        uint16_t R, s;
        schnorr_prove_cfg(priv, c, &R, &s, sd, &cfg);
        if (schnorr_verify_cfg(pub, c, R, s, &cfg)) ok++;
    }
    double dt = now_s() - t0;
    printf("schnorr+cat cache n=%-7d %.3fs  %10.1f ops/s  %8.2f us/op  ok=%d\n",
           n, dt, n / dt, dt / n * 1e6, ok);
}

static void bench_prng(uint32_t *sd, int n) {
    algo_config_t cfg; algo_config_default(&cfg);
    double t0 = now_s();
    uint32_t acc = 0;
    for (int i = 0; i < n; i++) acc ^= prng_next(sd, &cfg);
    double dt = now_s() - t0;
    printf("prng xorshift    n=%-7d %.3fs  %10.1f ops/s  %8.2f ns/op  acc=%08x\n",
           n, dt, n / dt, dt / n * 1e9, acc);
}

static void bench_compress(uint32_t *sd, int n) {
    uint8_t in[256], out[1024];
    for (int i = 0; i < 256; i++) in[i] = (uint8_t)(i / 4);
    int modes[] = { COMPRESS_RLE, COMPRESS_LZ4 };
    const char *names[] = { "rle", "lz4" };
    for (int m = 0; m < 2; m++) {
        double t0 = now_s();
        int total = 0;
        for (int i = 0; i < n; i++) {
            int r = compress_buf(modes[m], in, 256, out, sizeof(out));
            if (r > 0) total += r;
        }
        double dt = now_s() - t0;
        if (total == 0 && modes[m] == COMPRESS_LZ4) {
            printf("compress lz4     unavailable (no HAVE_LZ4)\n");
            continue;
        }
        printf("compress %-7s n=%-7d %.3fs  %10.1f ops/s  %8.2f us/op  avg_out=%d\n",
               names[m], n, dt, n / dt, dt / n * 1e6, total / n);
    }
}

static void bench_packet_overhead(uint32_t *sd, int n, int len) {
    algo_config_t cfg; algo_config_default(&cfg);
    uint16_t S = (uint16_t)(prng_next(sd, &cfg) & 0xFFFF);
    uint8_t buf[1024];
    for (int i = 0; i < len; i++) buf[i] = (uint8_t)i;
    double t0 = now_s();
    uint16_t ctr = 0;
    for (int i = 0; i < n; i++) {
        stream_xor_cfg(buf, (size_t)len, S, ctr, &cfg);
        mac_cfg(S, ctr, &cfg);
        ctr++;
    }
    double dt = now_s() - t0;
    double mbps = (double)n * len * 8.0 / dt / 1e6;
    printf("packet proc len=%-5d n=%-7d %.3fs  %10.1f pkt/s  %8.2f Mbps\n",
           len, n, dt, n / dt, mbps);
}

int main(void) {
    if (algo_self_test() != 0) { fprintf(stderr, "self-test failed\n"); return 1; }
    uint32_t sd = bench_seed();
    printf("bench: seed=%08x G=%u\n", sd, algo_g());
    printf("---------------------------------------------------------------\n");

    bench_modpow(&sd, 200000);
    bench_ks16(&sd, 2000000);
    bench_stream_xor(&sd, 200000, 64, CIPHER_KS16, "ks16");
    bench_stream_xor(&sd, 200000, 64, CIPHER_RAW, "raw");
    bench_stream_xor(&sd, 200000, 64, CIPHER_BLOCK, "block");
    bench_stream_xor(&sd, 20000, 1024, CIPHER_KS16, "ks16");
    bench_schnorr(&sd, 20000);
    bench_schnorr_cache(&sd, 20000);
    bench_prng(&sd, 5000000);
    bench_compress(&sd, 200000);
    bench_packet_overhead(&sd, 200000, 64);
    bench_packet_overhead(&sd, 20000, 1024);

    printf("---------------------------------------------------------------\n");
    printf("bench done, seed_after=%08x\n", sd);
    return 0;
}
