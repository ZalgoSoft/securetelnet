#include "negotiation.h"
#include "io.h"
#include <string.h>

static const char *const dh_names[] = {"normal", "test", 0};
static const char *const auth_names[] = {"schnorr", "hmac", 0};
static const char *const kdf_names[] = {"cube", "byte", "double", 0};
static const char *const cipher_names[] = {"ks16", "raw", "block", 0};
static const char *const mac_names[] = {"ks16", "precalc", 0};
static const char *const prng_names[] = {"xorshift", "mask", "clock", 0};
static const char *const compress_names[] = {"none", "rle", "lz4", 0};

static const char *id_to_name(const char *const *tbl, uint8_t id)
{
    uint8_t i;
    for (i = 0; tbl[i]; i++)
        if (i == id) return tbl[i];
    return 0;
}

static uint8_t name_to_id(const char *const *tbl, const char *name)
{
    uint8_t i;
    for (i = 0; tbl[i]; i++)
        if (strcmp(tbl[i], name) == 0) return i;
    return 0xFF;
}

const char *negotiation_dh_name(uint8_t id) { return id_to_name(dh_names, id); }
const char *negotiation_auth_name(uint8_t id) { return id_to_name(auth_names, id); }
const char *negotiation_kdf_name(uint8_t id) { return id_to_name(kdf_names, id); }
const char *negotiation_cipher_name(uint8_t id) { return id_to_name(cipher_names, id); }
const char *negotiation_mac_name(uint8_t id) { return id_to_name(mac_names, id); }
const char *negotiation_prng_name(uint8_t id) { return id_to_name(prng_names, id); }
const char *negotiation_compress_name(uint8_t id) { return id_to_name(compress_names, id); }

uint8_t negotiation_dh_id(const char *n) { return name_to_id(dh_names, n); }
uint8_t negotiation_auth_id(const char *n) { return name_to_id(auth_names, n); }
uint8_t negotiation_kdf_id(const char *n) { return name_to_id(kdf_names, n); }
uint8_t negotiation_cipher_id(const char *n) { return name_to_id(cipher_names, n); }
uint8_t negotiation_mac_id(const char *n) { return name_to_id(mac_names, n); }
uint8_t negotiation_prng_id(const char *n) { return name_to_id(prng_names, n); }
uint8_t negotiation_compress_id(const char *n) { return name_to_id(compress_names, n); }

static void pack(const negotiation_params_t *p, uint8_t out[9])
{
    out[0] = p->version;
    out[1] = p->dh;
    out[2] = p->auth;
    out[3] = p->schnorr_cache;
    out[4] = p->kdf;
    out[5] = p->cipher;
    out[6] = p->mac;
    out[7] = p->prng;
    out[8] = p->compress;
}

static void unpack(const uint8_t in[9], negotiation_params_t *p)
{
    p->version = in[0];
    p->dh = in[1];
    p->auth = in[2];
    p->schnorr_cache = in[3];
    p->kdf = in[4];
    p->cipher = in[5];
    p->mac = in[6];
    p->prng = in[7];
    p->compress = in[8];
}

static int intersect(uint8_t cli, uint8_t srv, uint8_t *out)
{
    if (cli == srv) { *out = cli; return 0; }
    return -1;
}

int negotiate_client(int fd, negotiation_params_t *cli, negotiation_params_t *srv)
{
    uint8_t buf[9];
    pack(cli, buf);
    if (io_write_full(fd, buf, 9) != 9) return -1;
    if (io_read_full(fd, buf, 9) != 9) return -1;
    unpack(buf, srv);
    if (srv->version == 0) return -1;
    if (srv->version != cli->version) return -1;
    return 0;
}

int negotiate_server(int fd, negotiation_params_t *srv, negotiation_params_t *cli)
{
    uint8_t in[9], out[9];
    negotiation_params_t got;
    negotiation_params_t result;
    if (io_read_full(fd, in, 9) != 9) return -1;
    unpack(in, &got);
    memset(&result, 0, sizeof(result));
    result.version = 0;
    if (got.version == srv->version) {
        if (intersect(got.dh, srv->dh, &result.dh) == 0 &&
            intersect(got.auth, srv->auth, &result.auth) == 0 &&
            intersect(got.kdf, srv->kdf, &result.kdf) == 0 &&
            intersect(got.cipher, srv->cipher, &result.cipher) == 0 &&
            intersect(got.mac, srv->mac, &result.mac) == 0 &&
            intersect(got.prng, srv->prng, &result.prng) == 0 &&
            intersect(got.compress, srv->compress, &result.compress) == 0)
        {
            result.version = srv->version;
            result.schnorr_cache = got.schnorr_cache & srv->schnorr_cache;
        }
    }
    pack(&result, out);
    if (io_write_full(fd, out, 9) != 9) return -1;
    if (result.version == 0) return -1;
    *cli = got;
    *cli = result;
    return 0;
}
