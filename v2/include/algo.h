#ifndef ALGO_H
#define ALGO_H

#include <stdint.h>
#include <stddef.h>

#define P 65519UL
#define D_INV 43679UL
#define NONCE_LEN 4

enum {
    DH_NORMAL = 0,
    DH_TEST = 1,
};

enum {
    AUTH_SCHNORR = 0,
    AUTH_HMAC = 1,
};

enum {
    KDF_CUBE = 0,
    KDF_BYTE = 1,
    KDF_DOUBLE = 2,
};

enum {
    CIPHER_KS16 = 0,
    CIPHER_RAW = 1,
    CIPHER_BLOCK = 2,
};

enum {
    MAC_KS16 = 0,
    MAC_PRECALC = 1,
};

enum {
    PRNG_XORSHIFT = 0,
    PRNG_MASK = 1,
    PRNG_CLOCK = 2,
};

enum {
    COMPRESS_NONE = 0,
    COMPRESS_RLE = 1,
    COMPRESS_LZ4 = 2,
};

typedef struct {
    int dh_mode;
    int auth_mode;
    int schnorr_cache;
    int kdf_mode;
    int cipher_mode;
    int mac_mode;
    int prng_mode;
    int compress_mode;
} algo_config_t;

void algo_config_default(algo_config_t *cfg);
int algo_parse_dh(const char *s);
int algo_parse_auth(const char *s);
int algo_parse_schnorr(const char *s);
int algo_parse_kdf(const char *s);
int algo_parse_cipher(const char *s);
int algo_parse_mac(const char *s);
int algo_parse_prng(const char *s);
int algo_parse_compress(const char *s);

uint16_t algo_g(void);
int algo_self_test(void);

uint16_t modpow(uint16_t base, uint32_t exp);
uint32_t prng_next(uint32_t *state, const algo_config_t *cfg);

uint16_t ks16(uint16_t S, uint16_t ctr);
uint16_t ks16_cfg(uint16_t S, uint16_t ctr, int kdf_mode);
uint8_t  ks_byte_cfg(uint16_t S, uint16_t ctr, uint8_t i, const algo_config_t *cfg);

void stream_xor_cfg(uint8_t *buf, size_t n, uint16_t S, uint16_t ctr,
                    const algo_config_t *cfg);

void schnorr_prove(uint16_t priv, uint16_t c, uint16_t *R, uint16_t *s,
                   uint32_t *seed);
int  schnorr_verify(uint16_t pub, uint16_t c, uint16_t R, uint16_t s);
void schnorr_prove_cfg(uint16_t priv, uint16_t c, uint16_t *R, uint16_t *s,
                       uint32_t *seed, const algo_config_t *cfg);
int  schnorr_verify_cfg(uint16_t pub, uint16_t c, uint16_t R, uint16_t s,
                        const algo_config_t *cfg);

int dh_client_cfg(int fd, uint16_t *S, uint32_t *ctr, uint32_t *seed,
                  const algo_config_t *cfg);
int dh_server_cfg(int fd, uint16_t *S, uint32_t *ctr, uint32_t *seed,
                  const algo_config_t *cfg);

uint16_t mac_cfg(uint16_t S, uint16_t ctr, const algo_config_t *cfg);

int auth_schnorr_server(int fd, const uint16_t *keys, int nkeys,
                        uint16_t S, uint32_t *seed, const algo_config_t *cfg);
int auth_schnorr_client(int fd, uint16_t priv, uint32_t *seed,
                        const algo_config_t *cfg);
int auth_hmac_server(int fd, const uint16_t *keys, int nkeys,
                     uint16_t S, uint32_t *seed, const algo_config_t *cfg);
int auth_hmac_client(int fd, uint16_t priv, uint16_t S,
                     const algo_config_t *cfg);

int read_full(int fd, void *buf, size_t n);
int write_full(int fd, const void *buf, size_t n);

#endif
