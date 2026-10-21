# API dump
root: `/home/user1/securetelnet/v3`
files: 16

## `include/algo.h`

### #define

- `#define ALGO_H `
- `#define P 65519UL`
- `#define D_INV 43679UL`
- `#define NONCE_LEN 4`

### enum

- `enum { DH_NORMAL = 0, DH_TEST = 1, } `
- `enum { AUTH_SCHNORR = 0, AUTH_HMAC = 1, } `
- `enum { KDF_CUBE = 0, KDF_BYTE = 1, KDF_DOUBLE = 2, } `
- `enum { CIPHER_KS16 = 0, CIPHER_RAW = 1, CIPHER_BLOCK = 2, } `
- `enum { MAC_KS16 = 0, MAC_PRECALC = 1, } `
- `enum { PRNG_XORSHIFT = 0, PRNG_MASK = 1, PRNG_CLOCK = 2, } `
- `enum { COMPRESS_NONE = 0, COMPRESS_RLE = 1, COMPRESS_LZ4 = 2, } `

### struct/union

- `struct { int dh_mode; int auth_mode; int schnorr_cache; int kdf_mode; int cipher_mode; int mac_mode; int prng_mode; int compress_mode; } algo_config_t`

### globals

- `int dh_mode;`
- `int auth_mode;`
- `int schnorr_cache;`
- `int kdf_mode;`
- `int cipher_mode;`
- `int mac_mode;`
- `int prng_mode;`
- `int compress_mode;`
- `} algo_config_t;`
- `const algo_config_t *cfg);`
- `uint32_t *seed);`
- `uint32_t *seed, const algo_config_t *cfg);`
- `const algo_config_t *cfg);`
- `const algo_config_t *cfg);`
- `const algo_config_t *cfg);`
- `uint16_t S, uint32_t *seed, const algo_config_t *cfg);`
- `const algo_config_t *cfg);`
- `uint16_t S, uint32_t *seed, const algo_config_t *cfg);`
- `const algo_config_t *cfg);`

### functions

- `void algo_config_default(algo_config_t *cfg)`
- `int algo_parse_dh(const char *s)`
- `int algo_parse_auth(const char *s)`
- `int algo_parse_schnorr(const char *s)`
- `int algo_parse_kdf(const char *s)`
- `int algo_parse_cipher(const char *s)`
- `int algo_parse_mac(const char *s)`
- `int algo_parse_prng(const char *s)`
- `int algo_parse_compress(const char *s)`
- `uint16_t algo_g(void)`
- `int algo_self_test(void)`
- `uint16_t modpow(uint16_t base, uint32_t exp)`
- `uint32_t prng_next(uint32_t *state, const algo_config_t *cfg)`
- `uint16_t ks16(uint16_t S, uint16_t ctr)`
- `uint16_t ks16_cfg(uint16_t S, uint16_t ctr, int kdf_mode)`
- `uint8_t ks_byte_cfg(uint16_t S, uint16_t ctr, uint8_t i, const algo_config_t *cfg)`
- `int schnorr_verify(uint16_t pub, uint16_t c, uint16_t R, uint16_t s)`
- `uint16_t mac_cfg(uint16_t S, uint16_t ctr, const algo_config_t *cfg)`
- `int read_full(int fd, void *buf, size_t n)`
- `int write_full(int fd, const void *buf, size_t n)`

## `include/client.h`

### #define

- `#define CLIENT_H `

### globals

- `const char *file_cmd, int overwrite);`

## `include/compress.h`

### #define

- `#define COMPRESS_H `

### functions

- `int rle_compress(const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap)`
- `int rle_decompress(const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap)`
- `int lz4_compress_wrap(const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap)`
- `int lz4_decompress_wrap(const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap)`
- `int compress_buf(int mode, const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap)`
- `int decompress_buf(int mode, const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap)`

## `include/keygen.h`

### #define

- `#define KEYGEN_H `

### functions

- `int keygen_run(const char *privpath, const char *pubpath)`

## `include/proto.h`

### #define

- `#define PROTO_H `
- `#define PROTO_VERSION 1`
- `#define MAX_PAYLOAD 65535`

### struct/union

- `struct { int version; int dh_mode; int auth_mode; int schnorr_cache; int kdf_mode; int cipher_mode; int mac_mode; int prng_mode; int compress_mode; } proto_params_t`

### globals

- `int version;`
- `int dh_mode;`
- `int auth_mode;`
- `int schnorr_cache;`
- `int kdf_mode;`
- `int cipher_mode;`
- `int mac_mode;`
- `int prng_mode;`
- `int compress_mode;`
- `} proto_params_t;`
- `uint16_t S, uint16_t *ctr, const algo_config_t *cfg);`
- `uint16_t S, uint16_t *ctr, const algo_config_t *cfg);`

### functions

- `void proto_params_from_algo(proto_params_t *pp, const algo_config_t *cfg)`
- `void algo_from_proto_params(algo_config_t *cfg, const proto_params_t *pp)`
- `void proto_params_default(proto_params_t *pp)`
- `int negotiate_client(int fd, proto_params_t *pp)`
- `int negotiate_server(int fd, proto_params_t *pp, const proto_params_t *server_caps)`

## `include/server.h`

### #define

- `#define SERVER_H `

### enum

- `enum { MODE_CHAT = 0, MODE_SHELL = 1, MODE_FILE = 2, } `

### globals

- `const proto_params_t *caps, const char *session_dir, int overwrite);`

## `include/session.h`

### #define

- `#define SESSION_H `

### struct/union

- `struct { FILE *log; char path[256]; time_t start; time_t last_rx; time_t last_tx; uint64_t packets_rx; uint64_t packets_tx; uint16_t S; int keepalive_interval; int keepalive_timeout; } session_t`

### globals

- `FILE *log;`
- `char path[256];`
- `time_t start;`
- `time_t last_rx;`
- `time_t last_tx;`
- `uint64_t packets_rx;`
- `uint64_t packets_tx;`
- `uint16_t S;`
- `int keepalive_interval;`
- `int keepalive_timeout;`
- `} session_t;`

### functions

- `int session_open(session_t *s, const char *dir)`
- `void session_close(session_t *s)`
- `void session_log(session_t *s, const char *fmt, ...)`
- `void session_note_rx(session_t *s)`
- `void session_note_tx(session_t *s)`
- `int session_keepalive_due(session_t *s)`
- `int session_timed_out(session_t *s)`

## `src/algo.c`

### globals

- `static uint16_t g_G = 0;`
- `cfg->dh_mode = DH_NORMAL;`
- `cfg->auth_mode = AUTH_SCHNORR;`
- `cfg->schnorr_cache = 0;`
- `cfg->kdf_mode = KDF_CUBE;`
- `cfg->cipher_mode = CIPHER_KS16;`
- `cfg->mac_mode = MAC_KS16;`
- `cfg->prng_mode = PRNG_XORSHIFT;`
- `cfg->compress_mode = COMPRESS_NONE;`
- `uint32_t result = 1;`
- `uint32_t b = base % P;`
- `exp >>= 1;`
- `uint32_t x = *state;`
- `x ^= x << 13; x ^= x >> 17; x ^= x << 5;`
- `*state = x;`
- `x %= P;`
- `uint8_t k;`
- `buf[i] ^= k;`
- `static uint16_t g_cache_pub = 0;`
- `static uint16_t g_cache_arr[256];`
- `static int g_cache_valid = 0;`
- `algo_config_t def;`
- `algo_config_t def;`
- `uint16_t pc;`
- `g_cache_pub = pub; g_cache_valid = 1;`
- `size_t got = 0;`
- `size_t sent = 0;`
- `uint16_t a;`
- `uint16_t A;`
- `uint8_t pkt[2 + NONCE_LEN];`
- `pkt[0] = A & 0xFF; pkt[1] = A >> 8;`
- `uint8_t resp[2 + NONCE_LEN];`
- `uint32_t peer_nonce = 0;`
- `*ctr = peer_nonce;`
- `uint8_t pkt[2 + NONCE_LEN];`
- `uint16_t b;`
- `uint8_t resp[2 + NONCE_LEN];`
- `resp[0] = B & 0xFF; resp[1] = B >> 8;`
- `uint32_t peer_nonce = 0;`
- `*ctr = peer_nonce;`
- `uint8_t pkt[2] = { c & 0xFF, c >> 8 };`
- `uint8_t resp[4];`
- `uint8_t nok[2] = {'N','K'};`
- `int ok = 0;`
- `uint8_t r[2] = { ok ? 'O' : 'N', 'K' };`
- `uint8_t pkt[2];`
- `uint16_t R, s;`
- `uint8_t resp[4] = { R & 0xFF, R >> 8, s & 0xFF, s >> 8 };`
- `uint8_t ok[2];`
- `uint8_t pkt[2] = { c & 0xFF, c >> 8 };`
- `uint8_t resp[2];`
- `int ok = 0;`
- `uint8_t r[2] = { ok ? 'O' : 'N', 'K' };`
- `uint8_t pkt[2];`
- `uint8_t resp[2] = { tag & 0xFF, tag >> 8 };`
- `uint8_t ok[2];`
- `uint32_t qs[] = {2, 7, 31, 151};`
- `int ok = 1;`

### functions

- `void algo_config_default(algo_config_t *cfg)`
- `int algo_parse_dh(const char *s)`
- `int algo_parse_auth(const char *s)`
- `int algo_parse_schnorr(const char *s)`
- `int algo_parse_kdf(const char *s)`
- `int algo_parse_cipher(const char *s)`
- `int algo_parse_mac(const char *s)`
- `int algo_parse_prng(const char *s)`
- `int algo_parse_compress(const char *s)`
- `uint16_t modpow(uint16_t base, uint32_t exp)`
- `uint32_t prng_next(uint32_t *state, const algo_config_t *cfg)`
- `uint16_t ks16(uint16_t S, uint16_t ctr)`
- `uint16_t ks16_cfg(uint16_t S, uint16_t ctr, int kdf_mode)`
- `uint8_t ks_byte_cfg(uint16_t S, uint16_t ctr, uint8_t i, const algo_config_t *cfg)`
- `int schnorr_verify(uint16_t pub, uint16_t c, uint16_t R, uint16_t s)`
- `uint16_t mac_cfg(uint16_t S, uint16_t ctr, const algo_config_t *cfg)`
- `static void fill_nonce(uint8_t *buf, size_t n, uint32_t *seed, const algo_config_t *cfg)`
- `int read_full(int fd, void *buf, size_t n)`
- `int write_full(int fd, const void *buf, size_t n)`
- `static uint16_t find_generator(void)`
- `int algo_self_test(void)`

## `src/client.c`

### struct/union

- `struct timeval tv = { .tv_sec = 5, .tv_usec = 0 } `
- `struct timeval tv = { .tv_sec = 5, .tv_usec = 0 } `
- `struct sockaddr_in addr = { 0 } `
- `struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("connect"); return 1; } session_t sess`

### globals

- `unsigned int v;`
- `fd_set rfds;`
- `char line[512];`
- `uint8_t in[1024];`
- `uint16_t inlen;`
- `int maxfd = fd > STDIN_FILENO ? fd : STDIN_FILENO;`
- `in[inlen] = 0;`
- `fd_set rfds;`
- `uint8_t in[1024];`
- `uint16_t inlen;`
- `char outbuf[1024];`
- `int maxfd = fd > STDIN_FILENO ? fd : STDIN_FILENO;`
- `uint8_t in[MAX_PAYLOAD];`
- `uint16_t inlen;`
- `const char *p = file_cmd + 4;`
- `char remote[256], local[256], cmd[512], final_local[PATH_MAX];`
- `remote[rl] = '\0';`
- `uint32_t got = 0;`
- `got += inlen;`
- `const char *p = file_cmd + 4;`
- `char local[256], remote[256], cmd[512];`
- `local[ll] = '\0';`
- `uint8_t buf[1024];`
- `size_t r;`
- `uint16_t priv;`
- `addr.sin_family = AF_INET;`
- `session_t sess;`
- `proto_params_t negotiated = *caps;`
- `algo_config_t cfg;`
- `uint16_t S = 0, ctr_tx = 0, ctr_rx = 0;`
- `uint32_t ctr32 = 0;`
- `sess.S = S;`
- `int ar;`
- `int r = 0;`

### functions

- `static int load_priv(const char *path, uint16_t *priv)`
- `else if(mode == MODE_SHELL) r = mode_shell(fd, &sess, S, ctr_tx, ctr_rx, &cfg)`
- `else if(mode == MODE_FILE) r = mode_file(fd, &sess, S, ctr_tx, ctr_rx, &cfg, file_cmd, overwrite)`

## `src/compress_lz4.c`

### functions

- `int lz4_compress_wrap(const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap)`
- `int lz4_decompress_wrap(const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap)`
- `int lz4_compress_wrap(const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap)`
- `int lz4_decompress_wrap(const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap)`
- `int compress_buf(int mode, const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap)`
- `int decompress_buf(int mode, const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap)`

## `src/compress_rle.c`

### globals

- `size_t o = 0, i = 0;`
- `uint8_t v = in[i];`
- `size_t run = 1;`
- `out[o++] = v;`
- `i += run;`
- `size_t o = 0, i = 0;`
- `uint8_t run = in[i++];`
- `uint8_t v = in[i++];`

### functions

- `int rle_compress(const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap)`
- `int rle_decompress(const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap)`

## `src/keygen.c`

### globals

- `algo_config_t cfg;`

### functions

- `int keygen_run(const char *privpath, const char *pubpath)`

## `src/main.c`

### globals

- `prog, prog, prog);`
- `*mode = MODE_CHAT;`
- `*shell = "/bin/sh";`
- `*session_dir = NULL;`
- `*file_cmd = NULL;`
- `*overwrite = 0;`
- `const char *a = argv[i];`
- `const char *v = argv[++i];`
- `else return -1;`
- `algo_config_t cfg;`
- `int mode, overwrite;`
- `const char *shell, *session_dir, *file_cmd;`
- `proto_params_t caps;`
- `proto_params_t caps;`
- `session_dir, file_cmd, overwrite);`

### functions

- `static void usage(const char *prog)`
- `int main(int argc, char **argv)`

## `src/proto.c`

### #define

- `#define COMPRESS_BUF 131072`

### globals

- `pp->version = PROTO_VERSION;`
- `pp->dh_mode = DH_NORMAL;`
- `pp->auth_mode = AUTH_SCHNORR;`
- `pp->schnorr_cache = 0;`
- `pp->kdf_mode = KDF_CUBE;`
- `pp->cipher_mode = CIPHER_KS16;`
- `pp->mac_mode = MAC_KS16;`
- `pp->prng_mode = PRNG_XORSHIFT;`
- `pp->compress_mode = COMPRESS_NONE;`
- `pp->version = PROTO_VERSION;`
- `pp->dh_mode = cfg->dh_mode;`
- `pp->auth_mode = cfg->auth_mode;`
- `pp->schnorr_cache = cfg->schnorr_cache;`
- `pp->kdf_mode = cfg->kdf_mode;`
- `pp->cipher_mode = cfg->cipher_mode;`
- `pp->mac_mode = cfg->mac_mode;`
- `pp->prng_mode = cfg->prng_mode;`
- `pp->compress_mode = cfg->compress_mode;`
- `cfg->dh_mode = pp->dh_mode;`
- `cfg->auth_mode = pp->auth_mode;`
- `cfg->schnorr_cache = pp->schnorr_cache;`
- `cfg->kdf_mode = pp->kdf_mode;`
- `cfg->cipher_mode = pp->cipher_mode;`
- `cfg->mac_mode = pp->mac_mode;`
- `cfg->prng_mode = pp->prng_mode;`
- `cfg->compress_mode = pp->compress_mode;`
- `pp->version = buf[0];`
- `pp->dh_mode = buf[1];`
- `pp->auth_mode = buf[2];`
- `pp->schnorr_cache = buf[3] ? 1 : 0;`
- `pp->kdf_mode = buf[4];`
- `pp->cipher_mode = buf[5];`
- `pp->mac_mode = buf[6];`
- `pp->prng_mode = buf[7];`
- `pp->compress_mode = buf[8];`
- `uint8_t buf[9];`
- `uint8_t resp[9];`
- `proto_params_t srv;`
- `proto_params_t out;`
- `out.version = PROTO_VERSION;`
- `out.compress_mode < 0) return -1;`
- `*pp = out;`
- `uint8_t buf[9];`
- `proto_params_t cli;`
- `uint8_t nok[9] = {0};`
- `nok[0] = 0;`
- `proto_params_t out;`
- `out.version = PROTO_VERSION;`
- `out.compress_mode >= 0;`
- `uint8_t rb[9];`
- `rb[0] = 0;`
- `*pp = out;`
- `static uint8_t g_cbuf[COMPRESS_BUF];`
- `uint8_t cbuf[COMPRESS_BUF];`
- `uint16_t clen = len;`
- `uint16_t c = *ctr;`
- `uint8_t hdr[4];`
- `hdr[0] = c & 0xFF; hdr[1] = c >> 8;`
- `hdr[2] = clen & 0xFF; hdr[3] = clen >> 8;`
- `uint8_t tb[2] = { tag & 0xFF, tag >> 8 };`
- `*ctr = c + 1;`
- `uint8_t hdr[4];`
- `uint8_t tb[2];`
- `*out_len = 0;`
- `*out_len = clen;`
- `*ctr = c + 1;`

### functions

- `void proto_params_default(proto_params_t *pp)`
- `void proto_params_from_algo(proto_params_t *pp, const algo_config_t *cfg)`
- `void algo_from_proto_params(algo_config_t *cfg, const proto_params_t *pp)`
- `static int pp_pack(const proto_params_t *pp, uint8_t *buf)`
- `static int pp_unpack(proto_params_t *pp, const uint8_t *buf)`
- `static int choose(int client, int server)`
- `int negotiate_client(int fd, proto_params_t *pp)`
- `int negotiate_server(int fd, proto_params_t *pp, const proto_params_t *caps)`

## `src/server.c`

### #define

- `#define MAX_KEYS 16`

### struct/union

- `struct timeval tv = { .tv_sec = 5, .tv_usec = 0 } `
- `struct timeval tv = { .tv_sec = 5, .tv_usec = 0 } `
- `struct sockaddr_in addr = { 0 } `
- `struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; } if (listen(sfd, 1) < 0) { perror("listen")`
- `struct sockaddr_in addr = { 0 } `
- `struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; } if (listen(sfd, 1) < 0) { perror("listen")`

### globals

- `int n = 0;`
- `unsigned int v;`
- `unsigned int v;`
- `uint32_t ctr32 = 0;`
- `out->kdf_mode, out->cipher_mode, out->compress_mode, out->mac_mode);`
- `int r;`
- `fd_set rfds;`
- `char line[512];`
- `uint8_t in[1024];`
- `uint16_t inlen;`
- `int maxfd = cfd > STDIN_FILENO ? cfd : STDIN_FILENO;`
- `in[inlen] = 0;`
- `int sv[2];`
- `fd_set rfds;`
- `uint8_t in[1024];`
- `uint16_t inlen;`
- `char outbuf[1024];`
- `int maxfd = cfd > sv[0] ? cfd : sv[0];`
- `int st;`
- `const char *p = path;`
- `uint8_t in[MAX_PAYLOAD];`
- `uint16_t inlen;`
- `in[inlen] = 0;`
- `const char *requested = cmd + 4;`
- `char final_path[PATH_MAX];`
- `uint8_t reply = f ? 'O' : 'N';`
- `uint8_t hdr[4];`
- `uint32_t got = 0;`
- `got += inlen;`
- `uint8_t nok = 'N';`
- `uint8_t ok = 'O';`
- `const char *requested = cmd + 4;`
- `uint8_t nok = 'N';`
- `uint8_t nok = 'N';`
- `uint8_t nok = 'N';`
- `uint8_t nok = 'N';`
- `uint8_t buf[1024];`
- `size_t r;`
- `int failed = 0;`
- `failed = 1;`
- `uint16_t keys[MAX_KEYS];`
- `int one = 1;`
- `addr.sin_family = AF_INET;`
- `addr.sin_addr.s_addr = INADDR_ANY;`
- `session_t sess;`
- `uint16_t S = 0;`
- `uint16_t ctr_tx = 0, ctr_rx = 0;`
- `proto_params_t negotiated;`
- `uint16_t keys[MAX_KEYS];`
- `int one = 1;`
- `addr.sin_family = AF_INET;`
- `addr.sin_addr.s_addr = INADDR_ANY;`
- `session_t sess;`
- `proto_params_t negotiated;`
- `algo_config_t cfg;`
- `uint16_t S = 0, ctr_tx = 0, ctr_rx = 0;`
- `sess.S = S;`
- `int r = 0;`

### functions

- `static int load_keys(const char *path, uint16_t *keys, int max)`
- `static int load_pub(const char *path, uint16_t *pub)`
- `static int path_is_safe(const char *path)`
- `else if(mode == MODE_SHELL) r = mode_shell(cfd, &sess, S, ctr_tx, ctr_rx, &cfg, shell)`
- `else if(mode == MODE_FILE) r = mode_file(cfd, &sess, S, ctr_tx, ctr_rx, &cfg, overwrite)`

## `src/session.c`

### globals

- `s->last_rx = s->start;`
- `s->last_tx = s->start;`
- `s->keepalive_interval = 30;`
- `s->keepalive_timeout = 90;`
- `tm.tm_hour, tm.tm_min, tm.tm_sec);`
- `s->log = NULL;`
- `tm.tm_hour, tm.tm_min, tm.tm_sec);`
- `va_list ap;`

### functions

- `int session_open(session_t *s, const char *dir)`
- `memset(s, 0, sizeof(*s)) sizeof(*s))`
- `void session_close(session_t *s)`
- `void session_log(session_t *s, const char *fmt, ...)`
- `void session_note_rx(session_t *s)`
- `void session_note_tx(session_t *s)`
- `int session_keepalive_due(session_t *s)`
- `int session_timed_out(session_t *s)`
