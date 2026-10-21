#ifndef NEGOTIATION_H
#define NEGOTIATION_H

#include <stdint.h>

typedef struct negotiation_params {
    uint8_t version;
    uint8_t dh;
    uint8_t auth;
    uint8_t schnorr_cache;
    uint8_t kdf;
    uint8_t cipher;
    uint8_t mac;
    uint8_t prng;
    uint8_t compress;
} negotiation_params_t;

int negotiate_client(int fd, negotiation_params_t *cli, negotiation_params_t *srv);
int negotiate_server(int fd, negotiation_params_t *srv, negotiation_params_t *cli);

const char *negotiation_dh_name(uint8_t id);
const char *negotiation_auth_name(uint8_t id);
const char *negotiation_kdf_name(uint8_t id);
const char *negotiation_cipher_name(uint8_t id);
const char *negotiation_mac_name(uint8_t id);
const char *negotiation_prng_name(uint8_t id);
const char *negotiation_compress_name(uint8_t id);

uint8_t negotiation_dh_id(const char *name);
uint8_t negotiation_auth_id(const char *name);
uint8_t negotiation_kdf_id(const char *name);
uint8_t negotiation_cipher_id(const char *name);
uint8_t negotiation_mac_id(const char *name);
uint8_t negotiation_prng_id(const char *name);
uint8_t negotiation_compress_id(const char *name);

#endif
