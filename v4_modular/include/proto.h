#ifndef PROTO_H
#define PROTO_H

#include <stdint.h>
#include <stddef.h>
#include "crypto/context.h"
#include "compress.h"

typedef struct proto_ctx {
    int fd;
    const crypto_ctx_t *crypto;
    const compress_ops_t *compress;
    uint16_t secret;
    uint16_t tx_counter;
    uint16_t rx_counter;
} proto_ctx_t;

proto_ctx_t *proto_new(int fd, const crypto_ctx_t *crypto, const compress_ops_t *compress, uint16_t secret);
void proto_free(proto_ctx_t *p);
int proto_send(proto_ctx_t *p, const uint8_t *payload, size_t len);
int proto_recv(proto_ctx_t *p, uint8_t *payload, size_t *len);

#endif
