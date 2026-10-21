#include "proto.h"
#include "compress.h"

#include <stdio.h>
#include <string.h>

#define COMPRESS_BUF 131072

void proto_params_default(proto_params_t *pp) {
    pp->version = PROTO_VERSION;
    pp->dh_mode = DH_NORMAL;
    pp->auth_mode = AUTH_SCHNORR;
    pp->schnorr_cache = 0;
    pp->kdf_mode = KDF_CUBE;
    pp->cipher_mode = CIPHER_KS16;
    pp->mac_mode = MAC_KS16;
    pp->prng_mode = PRNG_XORSHIFT;
    pp->compress_mode = COMPRESS_NONE;
}

void proto_params_from_algo(proto_params_t *pp, const algo_config_t *cfg) {
    pp->version = PROTO_VERSION;
    pp->dh_mode = cfg->dh_mode;
    pp->auth_mode = cfg->auth_mode;
    pp->schnorr_cache = cfg->schnorr_cache;
    pp->kdf_mode = cfg->kdf_mode;
    pp->cipher_mode = cfg->cipher_mode;
    pp->mac_mode = cfg->mac_mode;
    pp->prng_mode = cfg->prng_mode;
    pp->compress_mode = cfg->compress_mode;
}

void algo_from_proto_params(algo_config_t *cfg, const proto_params_t *pp) {
    cfg->dh_mode = pp->dh_mode;
    cfg->auth_mode = pp->auth_mode;
    cfg->schnorr_cache = pp->schnorr_cache;
    cfg->kdf_mode = pp->kdf_mode;
    cfg->cipher_mode = pp->cipher_mode;
    cfg->mac_mode = pp->mac_mode;
    cfg->prng_mode = pp->prng_mode;
    cfg->compress_mode = pp->compress_mode;
}

static int pp_pack(const proto_params_t *pp, uint8_t *buf) {
    buf[0] = (uint8_t)pp->version;
    buf[1] = (uint8_t)pp->dh_mode;
    buf[2] = (uint8_t)pp->auth_mode;
    buf[3] = (uint8_t)(pp->schnorr_cache ? 1 : 0);
    buf[4] = (uint8_t)pp->kdf_mode;
    buf[5] = (uint8_t)pp->cipher_mode;
    buf[6] = (uint8_t)pp->mac_mode;
    buf[7] = (uint8_t)pp->prng_mode;
    buf[8] = (uint8_t)pp->compress_mode;
    return 9;
}

static int pp_unpack(proto_params_t *pp, const uint8_t *buf) {
    pp->version = buf[0];
    pp->dh_mode = buf[1];
    pp->auth_mode = buf[2];
    pp->schnorr_cache = buf[3] ? 1 : 0;
    pp->kdf_mode = buf[4];
    pp->cipher_mode = buf[5];
    pp->mac_mode = buf[6];
    pp->prng_mode = buf[7];
    pp->compress_mode = buf[8];
    return 0;
}

static int choose(int client, int server) {
    return client == server ? client : -1;
}

int negotiate_client(int fd, proto_params_t *pp) {
    uint8_t buf[9];
    pp_pack(pp, buf);
    if (write_full(fd, buf, 9) < 0) return -1;

    uint8_t resp[9];
    if (read_full(fd, resp, 9) < 0) return -1;

    proto_params_t srv;
    pp_unpack(&srv, resp);
    if (srv.version != PROTO_VERSION) return -1;

    proto_params_t out;
    out.version = PROTO_VERSION;
    out.dh_mode = choose(pp->dh_mode, srv.dh_mode);
    out.auth_mode = choose(pp->auth_mode, srv.auth_mode);
    out.schnorr_cache = choose(pp->schnorr_cache, srv.schnorr_cache);
    out.kdf_mode = choose(pp->kdf_mode, srv.kdf_mode);
    out.cipher_mode = choose(pp->cipher_mode, srv.cipher_mode);
    out.mac_mode = choose(pp->mac_mode, srv.mac_mode);
    out.prng_mode = choose(pp->prng_mode, srv.prng_mode);
    out.compress_mode = choose(pp->compress_mode, srv.compress_mode);
    if (out.dh_mode < 0 || out.auth_mode < 0 || out.kdf_mode < 0 ||
        out.cipher_mode < 0 || out.mac_mode < 0 || out.prng_mode < 0 ||
        out.compress_mode < 0) return -1;

    *pp = out;
    return 0;
}

int negotiate_server(int fd, proto_params_t *pp, const proto_params_t *caps) {
    uint8_t buf[9];
    if (read_full(fd, buf, 9) < 0) return -1;
    proto_params_t cli;
    pp_unpack(&cli, buf);
    if (cli.version != PROTO_VERSION) {
        uint8_t nok[9] = {0};
        nok[0] = 0;
        write_full(fd, nok, 9);
        return -1;
    }
    proto_params_t out;
    out.version = PROTO_VERSION;
    out.dh_mode = choose(cli.dh_mode, caps->dh_mode);
    out.auth_mode = choose(cli.auth_mode, caps->auth_mode);
    out.schnorr_cache = choose(cli.schnorr_cache, caps->schnorr_cache);
    out.kdf_mode = choose(cli.kdf_mode, caps->kdf_mode);
    out.cipher_mode = choose(cli.cipher_mode, caps->cipher_mode);
    out.mac_mode = choose(cli.mac_mode, caps->mac_mode);
    out.prng_mode = choose(cli.prng_mode, caps->prng_mode);
    out.compress_mode = choose(cli.compress_mode, caps->compress_mode);
    int ok = out.dh_mode >= 0 && out.auth_mode >= 0 && out.kdf_mode >= 0 &&
             out.cipher_mode >= 0 && out.mac_mode >= 0 && out.prng_mode >= 0 &&
             out.compress_mode >= 0;
    uint8_t rb[9];
    if (!ok) {
        memset(rb, 0, 9);
        rb[0] = 0;
        write_full(fd, rb, 9);
        return -1;
    }
    pp_pack(&out, rb);
    if (write_full(fd, rb, 9) < 0) return -1;
    *pp = out;
    return 0;
}

static uint8_t g_cbuf[COMPRESS_BUF];

int send_packet(int fd, const uint8_t *data, uint16_t len,
                uint16_t S, uint16_t *ctr, const algo_config_t *cfg) {
    uint8_t cbuf[COMPRESS_BUF];
    uint16_t clen = len;
    if (len > 0 && cfg->compress_mode != COMPRESS_NONE) {
        int r = compress_buf(cfg->compress_mode, data, len, cbuf, sizeof(cbuf));
        if (r < 0) {
            fprintf(stderr, "compress failed\n");
            return -1;
        }
        if (r > (int)MAX_PAYLOAD) {
            fprintf(stderr, "compressed payload too large: %d\n", r);
            return -1;
        }
        memcpy(g_cbuf, cbuf, (size_t)r);
        clen = (uint16_t)r;
    } else if (len > 0) {
        memcpy(g_cbuf, data, len);
    }

    uint16_t c = *ctr;
    uint8_t hdr[4];
    hdr[0] = c & 0xFF; hdr[1] = c >> 8;
    hdr[2] = clen & 0xFF; hdr[3] = clen >> 8;
    if (write_full(fd, hdr, 4) < 0) return -1;

    if (clen > 0) {
        stream_xor_cfg(g_cbuf, clen, S, c, cfg);
        if (write_full(fd, g_cbuf, clen) < 0) return -1;
    }

    uint16_t tag = mac_cfg(S, c, cfg);
    uint8_t tb[2] = { tag & 0xFF, tag >> 8 };
    if (write_full(fd, tb, 2) < 0) return -1;

    *ctr = c + 1;
    return 0;
}
int recv_packet(int fd, uint8_t *out, uint16_t *out_len,
                uint16_t S, uint16_t *ctr, const algo_config_t *cfg) {
    uint8_t hdr[4];
    if (read_full(fd, hdr, 4) < 0) return -1;
    uint16_t c = (uint16_t)(hdr[0] | (hdr[1] << 8));
    uint16_t clen = (uint16_t)(hdr[2] | (hdr[3] << 8));
    if (clen > COMPRESS_BUF) return -1;

    if (clen > 0) {
        if (read_full(fd, g_cbuf, clen) < 0) return -1;
    }
    uint8_t tb[2];
    if (read_full(fd, tb, 2) < 0) return -1;
    uint16_t tag = (uint16_t)(tb[0] | (tb[1] << 8));
    uint16_t expect = mac_cfg(S, c, cfg);
    if (tag != expect) { fprintf(stderr, "MAC mismatch\n"); return -1; }

    if (clen > 0) stream_xor_cfg(g_cbuf, clen, S, c, cfg);

    if (clen == 0) {
        *out_len = 0;
    } else if (cfg->compress_mode != COMPRESS_NONE) {
        int r = decompress_buf(cfg->compress_mode, g_cbuf, clen, out, MAX_PAYLOAD);
        if (r < 0) { fprintf(stderr, "decompress failed\n"); return -1; }
        *out_len = (uint16_t)r;
    } else {
        memcpy(out, g_cbuf, clen);
        *out_len = clen;
    }
    *ctr = c + 1;
    return 0;
}

