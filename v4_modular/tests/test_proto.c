#include "proto.h"
#include "crypto/context.h"
#include "crypto/field.h"

#include "compress.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
extern uint16_t crypto_G;

int main(void)
{
    int sv[2];
    crypto_ctx_t cc, sc;
    const compress_ops_t *z;
    proto_ctx_t *cp, *sp;
    uint8_t out[256], in[256];
    size_t len;
    crypto_G = crypto_find_generator();
    if (crypto_init(&cc, "normal", "cube", "ks16", "ks16", "xorshift", "schnorr", 0) != 0) return 1;
    if (crypto_init(&sc, "normal", "cube", "ks16", "ks16", "xorshift", "schnorr", 0) != 0) return 1;
    for (z = compress_first(); z; z = compress_next(z)) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 1;
        cp = proto_new(sv[0], &cc, z, 1234);
        sp = proto_new(sv[1], &sc, z, 1234);
        memset(out, 0x55, sizeof(out));
        if (proto_send(cp, out, 32) != 0) { printf("send failed %s\n", z->name); return 1; }
        len = sizeof(in);
        if (proto_recv(sp, in, &len) != 0) { printf("recv failed %s\n", z->name); return 1; }
        printf("compress=%s sent=32 got=%zu\n", z->name, len);
        proto_free(cp); proto_free(sp);
        close(sv[0]); close(sv[1]);
    }
    return 0;
}
