#include "negotiation.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

int main(void)
{
    int sv[2];
    pid_t pid;
    negotiation_params_t cli, srv, peer;
    memset(&cli, 0, sizeof(cli));
    memset(&srv, 0, sizeof(srv));
    cli.version = srv.version = 1;
    cli.dh = srv.dh = 0;
    cli.auth = srv.auth = 0;
    cli.kdf = srv.kdf = 0;
    cli.cipher = srv.cipher = 0;
    cli.mac = srv.mac = 0;
    cli.prng = srv.prng = 0;
    cli.compress = srv.compress = 0;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 1;
    pid = fork();
    if (pid == 0) {
        close(sv[0]);
        negotiate_server(sv[1], &srv, &peer);
        close(sv[1]);
        _exit(0);
    }
    close(sv[1]);
    if (negotiate_client(sv[0], &cli, &peer) != 0) {
        printf("negotiation failed\n");
        close(sv[0]);
        return 1;
    }
    close(sv[0]);
    printf("negotiation ok dh=%s auth=%s kdf=%s cipher=%s mac=%s prng=%s compress=%s\n",
           negotiation_dh_name(peer.dh), negotiation_auth_name(peer.auth),
           negotiation_kdf_name(peer.kdf), negotiation_cipher_name(peer.cipher),
           negotiation_mac_name(peer.mac), negotiation_prng_name(peer.prng),
           negotiation_compress_name(peer.compress));
    return 0;
}
