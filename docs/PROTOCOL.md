# Protocol

Transport is TCP. All multi-byte fields are little-endian unless stated otherwise.

## 1. Connection setup

```
TCP SYN / SYN-ACK / ACK
negotiate   (client → server: 9 bytes, server → client: 9 bytes)
DH          (client → server: 6 bytes, server → client: 6 bytes)
auth        (server → client: 2 bytes, client → server: 4/2 bytes, server → client: 2 bytes)
data        (packets [ctr:2][len:2][ct][tag:2])
```

## 2. Negotiation

The client sends 9 bytes:
```
[version][dh][auth][schnorr_cache][kdf][cipher][mac][prng][compress]
```

The server reads them, compares with `caps` using strict equality on each field, and replies with the same 9 bytes; on any mismatch — `version = 0` (rejection), and the client closes the connection.

- `version`: `PROTO_VERSION = 1`.
- `dh`: `0 = normal`, `1 = test`.
- `auth`: `0 = schnorr`, `1 = hmac`.
- `schnorr_cache`: `0`/`1`.
- `kdf`: `0 = cube`, `1 = byte`, `2 = double`.
- `cipher`: `0 = ks16`, `1 = raw`, `2 = block`.
- `mac`: `0 = ks16`, `1 = precalc`.
- `prng`: `0 = xorshift`, `1 = mask`, `2 = clock`.
- `compress`: `0 = none`, `1 = rle`, `2 = lz4`.

Functions: `negotiate_client`, `negotiate_server`, `pp_pack`, `pp_unpack`, `choose`.

## 3. DH handshake

```
client → server: A[2] || nonce_c[4]     (6 bytes)
server → client: B[2] || nonce_s[4]     (6 bytes)
```

- `A = G^a mod P`, `B = G^b mod P`.
- `nonce` — 4 random bytes from `prng_next`.
- `S = B^a mod P = A^b mod P`.
- `ctr_tx = ctr_rx = peer_nonce` (low 16 bits; in the current implementation `*ctr = peer_nonce`, `uint32_t → uint16_t`).

Rejection: `A`/`B ∈ {0, 1, P-1}` or `≥ P`.

Functions: `dh_client_cfg`, `dh_server_cfg`.

## 4. Authentication

### 4.1. Schnorr

```
server → client: c[2]                   (c = ks16_cfg(S, rnd) ^ 0xFFFF, c ≠ 0)
client → server: R[2] || s[2]
server → client: "OK" | "NK"
```

- `R = G^r mod P`, `s = (r + c·priv) mod (P-1)`.
- The server checks `G^s == R·pub^c mod P` for each key in `authorized_keys`; sends a single `OK`/`NK`.
- `R = 0` is rejected.

Functions: `auth_schnorr_server`, `auth_schnorr_client`, `schnorr_prove_cfg`, `schnorr_verify_cfg`.

### 4.2. HMAC-like

```
server → client: c[2]
client → server: tag[2]                 (tag = ks16_cfg(S, priv ^ c))
server → client: "OK" | "NK"
```

Functions: `auth_hmac_server`, `auth_hmac_client`.

## 5. Data packet

```
[ ctr:2 ][ len:2 ][ ciphertext:len ][ tag:2 ]
```

- `ctr` — direction counter; `ctr_tx` and `ctr_rx` are independent, both start from `peer_nonce`.
- `len` — length **after** compression (may be larger than the original).
- `ciphertext = stream_xor_cfg(compress(plaintext), S, ctr, cfg)`.
- `tag = mac_cfg(S, ctr, cfg)`.
- `len = 0` — keepalive.

Recipient:
1. Checks `tag == mac_cfg(S, ctr)`; on mismatch — `MAC mismatch`, the session closes.
2. Decrypts with `stream_xor_cfg`.
3. If `compress_mode != none` — `decompress_buf`; otherwise copies.
4. Increments `ctr_rx`.

The sender increments `ctr_tx` after a successful write.

Functions: `send_packet`, `recv_packet`, `stream_xor_cfg`, `mac_cfg`, `compress_buf`, `decompress_buf`.

## 6. Session and keepalive

- Log: `<session_dir>/session_YYYYMMDD_HHMMSS.log` or `./session_YYYYMMDD_HHMMSS.log`.
- Logged: start, `dh ok S=...`, `negotiate ok ...`, `auth OK/FAIL`, `file put/get`, final counters.
- Keepalive: an empty packet (`len=0`) when `now - last_tx >= keepalive_interval` (30 s).
- Timeout: `now - last_rx >= keepalive_timeout` (90 s) → `session_timed_out` → exit from `mode_*`.

Functions: `session_open`, `session_close`, `session_log`, `session_note_rx/tx`, `session_keepalive_due`, `session_timed_out`.

## 7. `chat` mode

- `select` on stdin and the socket.
- Send: a line from `fgets`, `\n` is stripped, `send_packet`.
- Receive: `recv_packet`, print `\r<peer>> <text>\n<self>> `.
- `\r` overwrites the current input line so that an incoming message does not mix with what is being typed.
- Limitation: text typed but not yet sent is lost when an incoming message arrives (no `readline`/raw mode).

Functions: `mode_chat` (server and client).

## 8. `shell` mode

- Server `fork`/`execvp(shell)` on `socketpair(AF_UNIX, SOCK_STREAM)`; the child gets `dup2` onto stdin/stdout/stderr.
- Parent: `select` on the `socketpair` and the socket; data from the `socketpair` → `send_packet`, from `recv_packet` → `write` into the `socketpair`.
- Client: stdin → `send_packet`, `recv_packet` → stdout.
- `termios` raw is not enabled: `Ctrl-C` kills the client locally, not the remote shell. Arrows/`Ctrl-D` behave as in a normal terminal.

Functions: `mode_shell` (server and client).

## 9. `file` mode

### 9.1. `put <local> <remote>`

```
client → server: "put <remote>"
client → server: flen[2]           (file size)
client → server: data blocks       (send_packet, up to 1024 bytes each)
server → client: 'O' | 'N'
```

- `local` — path on the client, relative to the client's cwd.
- `remote` — path on the server, relative to the server's cwd; must pass `path_is_safe` (not absolute, no `..`).
- `--overwrite`: `fopen(remote, "wb")` (truncates).
- `--no-overwrite`: if `remote` exists, `remote.1`, `remote.2`, ... is chosen (`pick_write_path`).
- Rejection: `unsafe path`, `no free name`, `fopen` fail → `'N'`.

### 9.2. `get <remote> <local>`

```
client → server: "get <remote>"
server → client: flen[2] | 'N'     (size or rejection)
server → client: data blocks
client → server: (no reply, the client terminates)
```

- `remote` — path on the server, `path_is_safe`.
- `local` — path on the client, same `--overwrite`/`file.N` rule.
- Rejection: `unsafe path`, `fopen` fail, `sz > 0xFFFF` → `'N'`.

### 9.3. Size limit

`flen` is 2 bytes, so files > 65535 are rejected (`file too large`).
For files up to 4 GB you need:
- a 4-byte `flen` in the header,
- 1024/4096 blocks via the existing `send_packet` (already `uint16_t len`),
- `uint32_t got` in the receive loops.

See section "File transfer extensions".

Functions: `mode_file` (server and client), `path_is_safe`, `pick_write_path`.

## 10. File transfer extensions (for > 64 KB)

Minimal changes:
- `client.c` `put`: `uint32_t flen`, `hdr[4]`.
- `server.c` `put`: read `hdr[4]`, `uint32_t flen/got`.
- `server.c` `get`: `uint32_t flen`, `hdr[4]`.
- `client.c` `get`: read `hdr[4]`, `uint32_t flen/got`.
- `proto.c` is unchanged: `send_packet` already accepts `uint16_t len`, and 1024-byte blocks fit.

## 11. Security: what the protocol does and does not do

**Does:**
- XOR encryption of the payload with `S`.
- Client authentication (Schnorr/HMAC).
- Replay/reordering/loss of packets — via `ctr` and `tag`.
- File path sandbox (`path_is_safe`).
- Negotiation with rejection on incompatibility.

**Does not:**
- Server authentication (a MITM substitutes `B`).
- Forward secrecy (compromising `priv` or brute-forcing `a` reveals `S`).
- The MAC does not cover the payload — ciphertext substitution within a session is not detected.
- `c = 0` in Schnorr (probability `1/65536`) — forcibly replaced with `1`.
- Cryptographic strength: 16-bit DH, `x^3 mod P`, `xorshift32` — all educational.
- `termios` raw in shell mode — `Ctrl-C` kills the client.

## 12. What to add for a "real SSH"

| Feature | Complexity | Effect |
|---|---|---|
| Server authentication (`pub_server` + signature over `S`) | medium (~40 lines) | closes MITM |
| Re-keying after N packets/seconds | medium (~50 lines) | bounds the volume per `S` |
| 4-byte `flen` + blocks | low (~10 lines) | files up to 4 GB |
| `termios` raw + sending `SIGINT` as a byte | medium (~80 lines) | proper shell |
| MAC over `hash(S, ctr, ct)` instead of `ks16(S, ctr)` | low | detects payload substitution |
| Range-based preference negotiation | medium | selection flexibility |
| Port forwarding | high (~150 lines) | like `ssh -L` |

## 13. Edge cases

| Location | Problem | Solution |
|---|---|---|
| `send_packet` with `len=0` | `memcpy(NULL, 0)` — UB | pass `(const uint8_t*)""` |
| `MAX_PAYLOAD=65535` on the stack | 64 KB in `mode_file` | `static` buffer or reduce it |
| `ctr` overflow | `tag(0) = tag(0xFFFF)` | reset the session at `ctr=0xFFFF` |
| `authorized_keys` | read at startup, revocation requires restart | re-read on SIGHUP |
| `path_is_safe("sub/../x")` | rejects because of `..` | normalize before checking |
| `--no-overwrite` + `put` into an existing `up_name` | the server writes to `up_name.1`, the script looks for `up_name` | use `--overwrite` in automated tests |