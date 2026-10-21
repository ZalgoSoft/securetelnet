# API

Все заголовки — в `include/`. Все реализации — в `src/`. Компиляция: `-Iinclude`.

## Содержание

1. `algo.h` — примитивы.
2. `compress.h` — RLE и LZ4.
3. `proto.h` — пакеты и negotiation.
4. `session.h` — лог, keepalive.
5. `keygen.h` — генерация ключей.
6. `server.h` / `client.h` — режимы.
7. `main.c` — CLI.

## Константы и типы

### `algo.h`

| Имя | Значение | Назначение |
|---|---|---|
| `P` | `65519UL` | простое, `gcd(3, P-1)=1` |
| `D_INV` | `43679UL` | `3^(-1) mod (P-1)`, обратный показатель куба |
| `NONCE_LEN` | `4` | длина nonce в DH handshake |

`algo_config_t` — выбор алгоритмов:
```c
typedef struct {
    int dh_mode;        // DH_NORMAL | DH_TEST
    int auth_mode;      // AUTH_SCHNORR | AUTH_HMAC
    int schnorr_cache;  // 0 | 1
    int kdf_mode;       // KDF_CUBE | KDF_BYTE | KDF_DOUBLE
    int cipher_mode;    // CIPHER_KS16 | CIPHER_RAW | CIPHER_BLOCK
    int mac_mode;       // MAC_KS16 | MAC_PRECALC
    int prng_mode;      // PRNG_XORSHIFT | PRNG_MASK | PRNG_CLOCK
    int compress_mode;  // COMPRESS_NONE | COMPRESS_RLE | COMPRESS_LZ4
} algo_config_t;
```

### `proto.h`

| Имя | Значение | Назначение |
|---|---|---|
| `PROTO_VERSION` | `1` | версия negotiation |
| `MAX_PAYLOAD` | `65535` | верхняя граница payload |
| `COMPRESS_BUF` | `131072` | рабочий буфер сжатия (в `proto.c`) |

`proto_params_t` — wire-параметры negotiation: `version` + те же поля, что `algo_config_t`.

### `session.h`

`session_t`: `FILE *log`, `char path[256]`, `time_t start`, `last_rx`, `last_tx`, `uint64_t packets_rx`, `packets_tx`, `uint16_t S`, `int keepalive_interval`, `keepalive_timeout`.

### `server.h`

`MODE_CHAT = 0`, `MODE_SHELL = 1`, `MODE_FILE = 2`.

### `server.c`

`MAX_KEYS = 16` — предел `authorized_keys`.

## Функции

### `algo.h`

- `void algo_config_default(algo_config_t *cfg)` — заполняет значениями по умолчанию.
- `int algo_parse_dh/auth/schnorr/kdf/cipher/mac/prng/compress(const char *s)` — парсинг строковых значений; `-1` при ошибке.
- `uint16_t algo_g(void)` — текущий генератор `G`.
- `int algo_self_test(void)` — проверка `gcd(3,P-1)=1`, `D_INV`, `find_generator`, обратимости куба; `0` — успех.
- `uint16_t modpow(uint16_t base, uint32_t exp)` — `base^exp mod P`.
- `uint32_t prng_next(uint32_t *state, const algo_config_t *cfg)` — следующий xorshift32 с учётом `prng_mode`.
- `uint16_t ks16(uint16_t S, uint16_t ctr)` — `((S^ctr)|1)^3 mod P`.
- `uint16_t ks16_cfg(uint16_t S, uint16_t ctr, int kdf_mode)` — вариант KDF.
- `uint8_t ks_byte_cfg(uint16_t S, uint16_t ctr, uint8_t i, const algo_config_t *cfg)` — один байт keystream.
- `void stream_xor_cfg(uint8_t *buf, size_t n, uint16_t S, uint16_t ctr, const algo_config_t *cfg)` — XOR с keystream.
- `void schnorr_prove_cfg(...)` / `int schnorr_verify_cfg(...)` — Schnorr.
- `int dh_client_cfg(...)` / `int dh_server_cfg(...)` — DH.
- `uint16_t mac_cfg(uint16_t S, uint16_t ctr, const algo_config_t *cfg)` — тег.
- `int auth_schnorr_server/client(...)`, `int auth_hmac_server/client(...)` — авторизация.
- `int read_full(int fd, void *buf, size_t n)` / `int write_full(...)` — точный ввод-вывод.

### `compress.h`

- `int rle_compress/rle_decompress(...)`, `int lz4_compress_wrap/lz4_decompress_wrap(...)`, `int compress_buf/decompress_buf(int mode, ...)`.

### `proto.h`

- `void proto_params_default(proto_params_t *pp)`, `proto_params_from_algo`, `algo_from_proto_params`.
- `int negotiate_client(int fd, proto_params_t *pp)` / `int negotiate_server(int fd, proto_params_t *pp, const proto_params_t *caps)` — обмен 9 байтами.
- `int send_packet(...)` / `int recv_packet(...)` — пакет `[ctr:2][len:2][ct][tag:2]`.

### `session.h`

- `int session_open(session_t *s, const char *dir)` — создать `<dir>/session_<ts>.log`.
- `void session_close(session_t *s)`.
- `void session_log(session_t *s, const char *fmt, ...)` — с меткой времени.
- `void session_note_rx/tx(session_t *s)` — счётчики и `last_*`.
- `int session_keepalive_due(session_t *s)` / `int session_timed_out(session_t *s)`.

### `keygen.h`

- `int keygen_run(const char *privpath, const char *pubpath)`.

### `server.h` / `server.c`

- `int server_run(int port, const char *keyfile, int mode, const char *shell, const proto_params_t *caps, const char *session_dir, int overwrite)`.
- `static int load_keys/load_pub(const char *path, ...)`.
- `static int path_is_safe(const char *path)` — отсекает абсолютные пути и `..`.
- `static int pick_write_path(const char *requested, int overwrite, char *out, size_t outcap)` — `file.N` при `--no-overwrite`.
- `static int do_negotiate/do_handshake/do_auth(...)`.
- `static int mode_chat/mode_shell/mode_file(...)`.

### `client.h` / `client.c`

- `int client_run(const char *host, int port, const char *privfile, int mode, const char *shell, const proto_params_t *caps, const char *session_dir, const char *file_cmd, int overwrite)`.
- `static int load_priv(const char *path, uint16_t *priv)`.
- `static int mode_chat/mode_shell/mode_file(...)`.

### `main.c`

- `static void usage(const char *prog)`.
- `static int parse_algo_flags(...)`.
- `int main(int argc, char **argv)` — `keygen` / `server` / `client`.

## CLI

```
securetelnet keygen <privfile> <pubfile>
securetelnet server <port> <authorized_keys> [--mode chat|shell|file]
    [--shell /bin/sh] [--file-cmd 'get|put ...'] [--session-dir DIR]
    [--overwrite|--no-overwrite]
    [--kdf cube|byte|double] [--cipher ks16|raw|block]
    [--auth schnorr|hmac] [--schnorr plain|cache]
    [--mac ks16|precalc] [--prng xorshift|mask|clock]
    [--compress none|rle|lz4] [--dh normal|test]
securetelnet client <host> <port> <privfile> [те же опции]
```

`--overwrite` по умолчанию **выключен**: существующий файл переименовывается в `file.1`, `file.2`, ...

## Тестовые цели

- `tests/test_algo.c` — юнит-тесты примитивов (modpow, DH-симметрия, Schnorr completeness/soundness, `ks16`, `stream_xor`, PRNG, HMAC-auth).
- `tests/test_proto.c` — negotiation (ok/mismatch), roundtrip пакетов для всех `kdf`/`cipher`/`compress`.
- `tests/bench.c` — `modpow`, `ks16`, `stream_xor` (ks16/raw/block), Schnorr (plain/cache), PRNG, compression, packet processing.
- `tests/run_file_tests.sh` — матрица file-тестов с генерацией файлов в `tests/out/`, приёмом в `tests/in/`, сверкой SHA-256.