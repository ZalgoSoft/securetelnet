#ifndef PROTO_H
#define PROTO_H

#include "algo.h"
#include <stdint.h>
#include <stddef.h>

#define PROTO_VERSION 1
#define MAX_PAYLOAD 65535

typedef struct {
    int version;
    int dh_mode;
    int auth_mode;
    int schnorr_cache;
    int kdf_mode;
    int cipher_mode;
    int mac_mode;
    int prng_mode;
    int compress_mode;
} proto_params_t;

void proto_params_from_algo(proto_params_t *pp, const algo_config_t *cfg);
void algo_from_proto_params(algo_config_t *cfg, const proto_params_t *pp);
void proto_params_default(proto_params_t *pp);

int negotiate_client(int fd, proto_params_t *pp);
int negotiate_server(int fd, proto_params_t *pp, const proto_params_t *server_caps);

int send_packet(int fd, const uint8_t *data, uint16_t len,
                uint16_t S, uint16_t *ctr, const algo_config_t *cfg);
int recv_packet(int fd, uint8_t *out, uint16_t *out_len,
                uint16_t S, uint16_t *ctr, const algo_config_t *cfg);

#endif
