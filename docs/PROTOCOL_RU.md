# Protocol

Транспорт — TCP. Все многобайтовые поля little-endian, если не указано иное.

## 1. Установка соединения

```
TCP SYN / SYN-ACK / ACK
negotiate   (client → server: 9 байт, server → client: 9 байт)
DH          (client → server: 6 байт, server → client: 6 байт)
auth        (server → client: 2 байта, client → server: 4/2 байта, server → client: 2 байта)
data        (пакеты [ctr:2][len:2][ct][tag:2])
```

## 2. Negotiation

Клиент шлёт 9 байт:
```
[version][dh][auth][schnorr_cache][kdf][cipher][mac][prng][compress]
```

Сервер читает, сравнивает с `caps` строгим равенством по каждому полю, отвечает теми же 9 байтами; при любом несовпадении — `version = 0` (отказ), клиент закрывает соединение.

- `version`: `PROTO_VERSION = 1`.
- `dh`: `0 = normal`, `1 = test`.
- `auth`: `0 = schnorr`, `1 = hmac`.
- `schnorr_cache`: `0`/`1`.
- `kdf`: `0 = cube`, `1 = byte`, `2 = double`.
- `cipher`: `0 = ks16`, `1 = raw`, `2 = block`.
- `mac`: `0 = ks16`, `1 = precalc`.
- `prng`: `0 = xorshift`, `1 = mask`, `2 = clock`.
- `compress`: `0 = none`, `1 = rle`, `2 = lz4`.

Функции: `negotiate_client`, `negotiate_server`, `pp_pack`, `pp_unpack`, `choose`.

## 3. DH handshake

```
client → server: A[2] || nonce_c[4]     (6 байт)
server → client: B[2] || nonce_s[4]     (6 байт)
```

- `A = G^a mod P`, `B = G^b mod P`.
- `nonce` — 4 случайных байта из `prng_next`.
- `S = B^a mod P = A^b mod P`.
- `ctr_tx = ctr_rx = peer_nonce` (low 16 bits; в текущей реализации `*ctr = peer_nonce`, `uint32_t → uint16_t`).

Отказ: `A`/`B ∈ {0, 1, P-1}` или `≥ P`.

Функции: `dh_client_cfg`, `dh_server_cfg`.

## 4. Аутентификация

### 4.1. Schnorr

```
server → client: c[2]                   (c = ks16_cfg(S, rnd) ^ 0xFFFF, c ≠ 0)
client → server: R[2] || s[2]
server → client: "OK" | "NK"
```

- `R = G^r mod P`, `s = (r + c·priv) mod (P-1)`.
- Сервер проверяет `G^s == R·pub^c mod P` для каждого ключа в `authorized_keys`; шлёт один `OK`/`NK`.
- `R = 0` отвергается.

Функции: `auth_schnorr_server`, `auth_schnorr_client`, `schnorr_prove_cfg`, `schnorr_verify_cfg`.

### 4.2. HMAC-like

```
server → client: c[2]
client → server: tag[2]                 (tag = ks16_cfg(S, priv ^ c))
server → client: "OK" | "NK"
```

Функции: `auth_hmac_server`, `auth_hmac_client`.

## 5. Data packet

```
[ ctr:2 ][ len:2 ][ ciphertext:len ][ tag:2 ]
```

- `ctr` — счётчик направления; `ctr_tx` и `ctr_rx` независимы, оба стартуют с `peer_nonce`.
- `len` — длина **после** компрессии (может быть больше исходной).
- `ciphertext = stream_xor_cfg(compress(plaintext), S, ctr, cfg)`.
- `tag = mac_cfg(S, ctr, cfg)`.
- `len = 0` — keepalive.

Получатель:
1. Проверяет `tag == mac_cfg(S, ctr)`; при несовпадении — `MAC mismatch`, сессия закрывается.
2. Расшифровывает `stream_xor_cfg`.
3. Если `compress_mode != none` — `decompress_buf`; иначе копирует.
4. Инкрементирует `ctr_rx`.

Отправитель инкрементирует `ctr_tx` после успешной записи.

Функции: `send_packet`, `recv_packet`, `stream_xor_cfg`, `mac_cfg`, `compress_buf`, `decompress_buf`.

## 6. Session и keepalive

- Лог: `<session_dir>/session_YYYYMMDD_HHMMSS.log` или `./session_YYYYMMDD_HHMMSS.log`.
- В лог пишутся: старт, `dh ok S=...`, `negotiate ok ...`, `auth OK/FAIL`, `file put/get`, финальные счётчики.
- Keepalive: пустой пакет (`len=0`) при `now - last_tx >= keepalive_interval` (30 с).
- Таймаут: `now - last_rx >= keepalive_timeout` (90 с) → `session_timed_out` → выход из `mode_*`.

Функции: `session_open`, `session_close`, `session_log`, `session_note_rx/tx`, `session_keepalive_due`, `session_timed_out`.

## 7. Режим `chat`

- `select` на stdin и сокете.
- Отправка: строка из `fgets`, `\n` срезается, `send_packet`.
- Приём: `recv_packet`, печать `\r<peer>> <text>\n<self>> `.
- `\r` затирает текущую строку ввода, чтобы входящее сообщение не смешивалось с набираемым.
- Ограничение: набранный, но не отправленный текст теряется при входящем сообщении (нет `readline`/raw-mode).

Функции: `mode_chat` (server и client).

## 8. Режим `shell`

- Сервер `fork`/`execvp(shell)` на `socketpair(AF_UNIX, SOCK_STREAM)`; ребёнку `dup2` на stdin/stdout/stderr.
- Родитель: `select` на `socketpair` и сокете; данные из `socketpair` → `send_packet`, из `recv_packet` → `write` в `socketpair`.
- Клиент: stdin → `send_packet`, `recv_packet` → stdout.
- `termios` raw не включён: `Ctrl-C` убивает клиента локально, а не удалённый shell. Стрелки/`Ctrl-D` работают как в обычном терминале.

Функции: `mode_shell` (server и client).

## 9. Режим `file`

### 9.1. `put <local> <remote>`

```
client → server: "put <remote>"
client → server: flen[2]           (размер файла)
client → server: data blocks       (send_packet, до 1024 байт каждый)
server → client: 'O' | 'N'
```

- `local` — путь на клиенте, относительно cwd клиента.
- `remote` — путь на сервере, относительно cwd сервера; должен пройти `path_is_safe` (не абсолютный, без `..`).
- `--overwrite`: `fopen(remote, "wb")` (затирает).
- `--no-overwrite`: если `remote` существует, выбирается `remote.1`, `remote.2`, ... (`pick_write_path`).
- Отказ: `unsafe path`, `no free name`, `fopen` fail → `'N'`.

### 9.2. `get <remote> <local>`

```
client → server: "get <remote>"
server → client: flen[2] | 'N'     (размер или отказ)
server → client: data blocks
client → server: (нет ответа, клиент завершается)
```

- `remote` — путь на сервере, `path_is_safe`.
- `local` — путь на клиенте, то же правило `--overwrite`/`file.N`.
- Отказ: `unsafe path`, `fopen` fail, `sz > 0xFFFF` → `'N'`.

### 9.3. Ограничение размера

`flen` — 2 байта, поэтому файлы > 65535 отвергаются (`file too large`).
Для файлов до 4 ГБ нужно:
- 4-байтовый `flen` в заголовке,
- блоки по 1024/4096 через существующий `send_packet` (уже `uint16_t len`),
- `uint32_t got` в циклах приёма.

См. раздел «File transfer extensions».

Функции: `mode_file` (server и client), `path_is_safe`, `pick_write_path`.

## 10. File transfer extensions (для > 64 КБ)

Минимальные изменения:
- `client.c` `put`: `uint32_t flen`, `hdr[4]`.
- `server.c` `put`: читать `hdr[4]`, `uint32_t flen/got`.
- `server.c` `get`: `uint32_t flen`, `hdr[4]`.
- `client.c` `get`: читать `hdr[4]`, `uint32_t flen/got`.
- `proto.c` не меняется: `send_packet` уже принимает `uint16_t len`, блоки по 1024 проходят.

## 11. Безопасность: что протокол делает и чего не делает

**Делает:**
- XOR-шифрование payload на `S`.
- Аутентификация клиента (Schnorr/HMAC).
- Replay/перестановка/потеря пакетов — через `ctr` и `tag`.
- Sandbox файловых путей (`path_is_safe`).
- Negotiation с отказом при несовместимости.

**Не делает:**
- Аутентификация сервера (MITM подменяет `B`).
- Forward secrecy (компрометация `priv` или перебор `a` раскрывает `S`).
- MAC не покрывает payload — подмена ciphertext внутри сессии не детектируется.
- `c = 0` в Schnorr (вероятность `1/65536`) — принудительно заменяется на `1`.
- Криптостойкость: 16-бит DH, `x^3 mod P`, `xorshift32` — всё учебное.
- `termios` raw в shell-режиме — `Ctrl-C` убивает клиента.

## 12. Что стоит добавить для «настоящего SSH»

| Функция | Сложность | Эффект |
|---|---|---|
| Аутентификация сервера (`pub_server` + подпись `S`) | средняя (~40 строк) | закрывает MITM |
| Re-keying после N пакетов/секунд | средняя (~50 строк) | ограничивает объём на одном `S` |
| 4-байтовый `flen` + блоки | низкая (~10 строк) | файлы до 4 ГБ |
| `termios` raw + передача `SIGINT` как байта | средняя (~80 строк) | нормальный shell |
| MAC по `hash(S, ctr, ct)` вместо `ks16(S, ctr)` | низкая | детект подмены payload |
| Negotiation по диапазонам предпочтений | средняя | гибкость выбора |
| Порт-форвардинг | высокая (~150 строк) | как `ssh -L` |

## 13. Предельные случаи

| Место | Проблема | Решение |
|---|---|---|
| `send_packet` при `len=0` | `memcpy(NULL, 0)` — UB | передавать `(const uint8_t*)""` |
| `MAX_PAYLOAD=65535` на стеке | 64 КБ в `mode_file` | `static` буфер или уменьшить |
| `ctr` переполнение | `tag(0) = tag(0xFFFF)` | сброс сессии при `ctr=0xFFFF` |
| `authorized_keys` | читается при старте, отзыв — рестарт | перечитывать по SIGHUP |
| `path_is_safe("sub/../x")` | отвергает из-за `..` | нормализовать перед проверкой |
| `--no-overwrite` + `put` в существующий `up_name` | сервер пишет в `up_name.1`, скрипт ищет `up_name` | использовать `--overwrite` в автотестах |
