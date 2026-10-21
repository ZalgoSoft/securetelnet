#include "proto.h"
#include "io.h"
#include "common.h"
#include <stdlib.h>
#include <string.h>

static void put_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static uint16_t get_le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

proto_ctx_t *proto_new(int fd, const crypto_ctx_t *crypto, const compress_ops_t *compress, uint16_t secret)
{
    proto_ctx_t *p = calloc(1, sizeof(*p));
    if (!p) return 0;
    p->fd = fd;
    p->crypto = crypto;
    p->compress = compress;
    p->secret = secret;
    p->tx_counter = secret;
    p->rx_counter = secret;
    return p;
}

void proto_free(proto_ctx_t *p)
{
    free(p);
}

int proto_send(proto_ctx_t *p, const uint8_t *payload, size_t len)
{
    uint8_t hdr[PKT_HDR_LEN];
    uint8_t work[MAX_PAYLOAD];
    uint8_t tag[PKT_TAG_LEN];
    size_t work_len = 0;
    uint16_t mac;
    if (len > MAX_PAYLOAD) return -1;
    if (p->compress) {
        work_len = sizeof(work);
        if (p->compress->compress(payload, len, work, &work_len) != 0) return -1;
    } else {
        memcpy(work, payload, len);
        work_len = len;
    }
    p->crypto->cipher->xor(p->crypto->kdf, p->secret, p->tx_counter, work, work_len);
    mac = p->crypto->mac->tag(p->crypto->kdf, p->secret, p->tx_counter);
    put_le16(hdr, p->tx_counter);
    put_le16(hdr + 2, (uint16_t)work_len);
    tag[0] = (uint8_t)(mac & 0xFF);
    tag[1] = (uint8_t)((mac >> 8) & 0xFF);
    if (io_write_full(p->fd, hdr, PKT_HDR_LEN) != PKT_HDR_LEN) return -1;
    if (io_write_full(p->fd, work, work_len) != (ssize_t)work_len) return -1;
    if (io_write_full(p->fd, tag, PKT_TAG_LEN) != PKT_TAG_LEN) return -1;
    p->tx_counter++;
    return 0;
}

int proto_recv(proto_ctx_t *p, uint8_t *payload, size_t *len)
{
    uint8_t hdr[PKT_HDR_LEN];
    uint8_t work[MAX_PAYLOAD];
    uint8_t tag[PKT_TAG_LEN];
    uint8_t raw[MAX_PAYLOAD];
    uint16_t cnt, plen, mac, expect;
    size_t out_len;
    if (io_read_full(p->fd, hdr, PKT_HDR_LEN) != PKT_HDR_LEN) return -1;
    cnt = get_le16(hdr);
    plen = get_le16(hdr + 2);
    if (cnt != p->rx_counter) return -1;
    if (io_read_full(p->fd, work, plen) != (ssize_t)plen) return -1;
    if (io_read_full(p->fd, tag, PKT_TAG_LEN) != PKT_TAG_LEN) return -1;
    mac = (uint16_t)(tag[0] | ((uint16_t)tag[1] << 8));
    expect = p->crypto->mac->tag(p->crypto->kdf, p->secret, p->rx_counter);
    if (mac != expect) return -1;
    p->crypto->cipher->xor(p->crypto->kdf, p->secret, p->rx_counter, work, plen);
    if (p->compress) {
        out_len = *len;
        if (p->compress->decompress(work, plen, raw, &out_len) != 0) return -1;
        if (out_len > *len) return -1;
        memcpy(payload, raw, out_len);
        *len = out_len;
    } else {
        if (plen > *len) return -1;
        memcpy(payload, work, plen);
        *len = plen;
    }
    p->rx_counter++;
    return 0;
}
