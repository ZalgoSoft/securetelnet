# Limitations

This document lists the known limitations, pitfalls, and future work items of the `securetelnet` project.
The project is **educational**: 16-bit arithmetic, hand-rolled primitives, no external
crypto libraries. Everything below is a consequence of that choice, not a list of bugs that need
to be fixed immediately. For each item, it states exactly what is limited and how to work around it
if needed.

## 1. Cryptographic strength

### 1.1. 16-bit DH

`S = G^(a·b) mod P`, `P = 65519`, `P-1 = 65518 = 2·7·31·151`.

- Secret space `a, b ∈ [1, P-2] ≈ 2^16`.
- BSGS: ~256 steps and ~256 memory → **milliseconds** on a modern CPU.
- Brute-forcing `a` from `A = G^a mod P` is trivial.
- **Consequence:** any passive observer recovers `S` from the handshake.
- **Workaround:** switch to Curve25519 (32-byte keys, 32-bit arithmetic) or
  DH on `P ≥ 2^2048` (doesn't fit in AVR, fits in x86).

### 1.2. `ks16` is not a cryptographically strong OWF

`ks16(S, ctr) = (((S^ctr) | 1) mod P)^3 mod P`.

- `x^3 mod P` is **invertible** given `D_INV = 3^(-1) mod (P-1) = 43679`.
- `D_INV` is public (a constant in `algo.h`), `P-1` factors in milliseconds.
- **Consequence:** `ks16` is a bijection, not an OWF; given a known plaintext-ciphertext
  pair it yields the keystream, from which `S` is recovered by brute-forcing 65536 values.
- **Workaround:** ChaCha20 / SipHash-2-4 / SHA-256 (external libraries).

### 1.3. MAC does not cover the data

`tag = ks16(S, ctr ^ 0xFFFF)` — 2 bytes, depends only on `S` and `ctr`.

- **Protects against:** replay (different `ctr` → different `tag`), packet reordering, loss.
- **Does not protect against:** ciphertext substitution within a session. A packet can be replaced
  while keeping `ctr` and `tag`; the recipient decrypts garbage, and `tag` still matches.
- **Consequence:** payload integrity is not guaranteed.
- **Workaround:** `tag = HMAC(hash(S), ctr || ciphertext)` or AEAD (ChaCha20-Poly1305).

### 1.4. PRNG `xorshift32`

- Not cryptographically strong: state is 32 bits, predictable given the seed.
- Seed: `time(NULL) ^ (getpid() << 16) ^ clock()` — predictable.
- **Consequence:** `r` in Schnorr and the nonce in DH are predictable; reusing `r`
  across different `c` reveals `priv` (`(s1-s2)/(c1-c2) = priv`).
- **Workaround:** `getrandom()` / `/dev/urandom` for the seed and for `r`.

### 1.5. No server authentication

- The client only checks the server's `B` for range, not a signature.
- **Consequence:** a MITM substitutes `B`, sits in the middle; the client's Schnorr is useless
  against such a MITM (it relays the proof).
- **Future work:** `load_pub` already exists in `server.c` but is not called.
- **Workaround:** the server signs `S` (or `B || nonce_s`) with its `priv_server`,
  and the client verifies via `schnorr_verify_cfg(pub_server, ...)`.

### 1.6. No forward secrecy

- `S` is fixed for the session; if `priv` is compromised or `a` is brute-forced, `S` is revealed
  for **all** past sessions if traffic was recorded.
- **Workaround:** re-keying after N packets/seconds (a new DH on top of the current channel,
  the old `S` is wiped).

### 1.7. `c = 0` in Schnorr

- `c = ks16_cfg(S, rnd) ^ 0xFFFF` can be `0` with probability `1/65536`.
- With `c = 0`: `s = r`, `G^s = R` — verification passes **without knowing `priv`**.
- **Current state:** `c` is forcibly replaced with `1` in `auth_schnorr_server`.
- **Workaround:** already done; for strictness, generate `c` in `[1, P-2]` directly.

### 1.8. `R = 0` in Schnorr

- `R = 0` is impossible for `r ∈ [1, P-2]` (since `G^r ≠ 0 mod P` for prime `P`),
  but if it were — `rhs = 0`, `lhs = G^s ≠ 0` → verify would fail.
- **Current state:** the server explicitly rejects `R = 0` (`if (R == 0)`).

### 1.9. `ks16` collisions

- `(c, c^1)` with even `(S^c)` yield the same `x` after `|1`, hence the same `ks16`.
- Probability `~1/32768` per random `(S, c)` pair.
- **Consequence:** the keystream may repeat across two adjacent `ctr`.
- **Current state:** not fixed; `test_algo` prints the `observed/expected` estimate
  without `FAIL`.
- **Workaround:** drop `| 1` and use `x = (x == 0) ? 1 : x;` — collisions remain
  for `(c, c^1)` when `x = 1`, but disappear otherwise.

### 1.10. MAC collision `tag(0) = tag(0xFFFF)`

- `tag = ks16(S, ctr ^ 0xFFFF)`; `ctr = 0` and `ctr = 0xFFFF` yield the same `tag`.
- **Consequence:** when the `uint16_t` counter overflows (65,536 packets), a tag
  collision is possible.
- **Current state:** 65,536 packets per session is unlikely, but possible for
  a long session.
- **Workaround:** at `ctr == 0xFFFF` — reset the session (new DH) or switch to `uint32_t ctr`.

## 2. Protocol

### 2.1. Negotiation — strict equality

- `choose(client, server)` returns `client` only if `client == server`, otherwise `-1`.
- **Consequence:** a client with `--kdf byte` and a server with `--kdf cube` won't agree.
- **Workaround:** range-based negotiation of preferences (the client sends a list, the server picks
  the first common one).

### 2.2. `version = 0` as rejection

- On incompatibility the server sends 9 zero bytes (`version = 0`).
- The client treats `version != PROTO_VERSION` as `negotiate failed`.
- **Limitation:** no extensible list of rejection reasons.

### 2.3. `ctr_tx` and `ctr_rx` are independent

- Both start from `peer_nonce` (low 16 bits), then increment independently.
- **Consequence:** packet order in each direction is preserved by TCP; on packet loss
  (which TCP does not allow) the counters would diverge.
- **Limitation:** no reordering window, no out-of-order packet handling
  (not needed for TCP, but needed for a UDP transport).

### 2.4. `MAX_PAYLOAD = 65535`

- `uint16_t len` in `send_packet`/`recv_packet`.
- **Consequence:** one packet ≤ 64 KB; files > 64 KB are rejected in `mode_file`
  (`uint16_t flen`).
- **Workaround:** 4-byte `flen` + 1024/4096 blocks (see `docs/PROTOCOL.md`,
  section "File transfer extensions").

### 2.5. Keepalive and timeout

- `keepalive_interval = 30 s`, `keepalive_timeout = 90 s` — constants in `session_open`.
- **Consequence:** during long idle periods both sides send empty packets; on disconnect
  the session closes after 90 s.
- **Limitation:** not configurable via CLI (only by editing the code).

### 2.6. `session_open` and name collisions

- Path: `<dir>/session_YYYYMMDD_HHMMSS.log`.
- **Consequence:** two parallel runs in the same second with the same `dir` produce
  one file (the second `fopen("w")` overwrites the first).
- **Workaround:** add `pid` or a counter to the name.

## 3. File mode

### 3.1. `flen` is 2 bytes

- Files > 65535 bytes are rejected (`file too large`).
- **Workaround:** 4-byte `flen` + blocks (see `docs/PROTOCOL.md`).

### 3.2. `path_is_safe` rejects `..` even after normalization

- `path_is_safe("sub/../x")` → `0` (because of `..`), even though after normalization the path is safe.
- **Consequence:** you cannot use relative paths with `..` to leave and return
  into a subdirectory.
- **Workaround:** normalize the path (`realpath`) before checking, or explicitly allow
  `..` inside `cwd`.

### 3.3. `--no-overwrite` + automated tests

- With `--no-overwrite` the server writes to `remote.1`, `remote.2`, ... if `remote` is taken.
- **Consequence:** an automated test that expects `remote` won't find the file.
- **Current state:** `tests/run_file_tests.sh` uses `--overwrite` by default.

### 3.4. `put` and `get` use the same `<path>` on both sides

- `put <local> <remote>` and `get <remote> <local>` — with two paths (after the patch).
- **Limitation:** no way to transfer a file "into a temporary directory" without an explicit path.
- **Workaround:** specify a full relative path in `--file-cmd`.

### 3.5. `get` does not reply to the server

- After receiving the file the client terminates, the server waits on `recv_packet` → EOF → `break`.
- **Consequence:** no explicit `ACK` from the client; the server does not know that the client saved the file.
- **Limitation:** if the client disconnects, the server cannot distinguish "saved" from "crashed".
- **Workaround:** add a final `ACK` from the client (1 byte) and wait for it on the server.

## 4. Shell mode

### 4.1. No `termios` raw

- `Ctrl-C` kills the client locally, not the remote shell.
- Arrows/`Ctrl-D` behave as in a normal terminal (line buffering).
- **Consequence:** shell mode is inconvenient for interactive work.
- **Workaround:** `termios` raw on the client + sending `SIGINT` as byte `0x03`
  in the stream; on the server — `write` into the child's `socketpair`.

### 4.2. `fork`/`execvp` — Linux/POSIX only

- On Windows shell mode does not work without `_spawn`/`CreateProcess`.
- **Limitation:** the project targets Linux.

### 4.3. No shell resource limits

- `execvp(shell)` without `setrlimit`/`chroot`/`setuid`.
- **Consequence:** the shell has the same privileges as the server.
- **Workaround:** `setuid`/`setgid`/`chroot` before `execvp` (requires root).

## 5. Chat mode

### 5.1. No `readline`

- `fgets` + `select` + `\r` redraw.
- **Consequence:** text typed but not yet sent is lost when an incoming message arrives.
- **Workaround:** GNU `readline` or raw mode + a custom input line.

### 5.2. No history, editing, completion

- `fgets` limitation: no arrows, `Ctrl-A`, `Ctrl-E`, etc.

### 5.3. Prompt breaks on incoming message without `\r`

- `mode_chat` uses `printf("\r<peer>> %s\n<self>> ", ...)`.
- **Consequence:** if `\r` is removed, the prompt "slides" onto a new line.
- **Current state:** `\r` is enabled.

## 6. Resources

### 6.1. `MAX_PAYLOAD = 65535` on the stack

- `mode_file` keeps `uint8_t in[MAX_PAYLOAD]` on the stack — 64 KB.
- `send_packet` keeps `uint8_t cbuf[COMPRESS_BUF]` — 128 KB on the stack.
- **Consequence:** fine on x86-64 (8 MB stack), but stack overflow on AVR/ESP32.
- **Workaround:** `static` buffers or reduce `COMPRESS_BUF`/`MAX_PAYLOAD` to 512/4096.

### 6.2. `g_cbuf[COMPRESS_BUF]` — global 128 KB buffer

- In `proto.c` — global, not on the stack.
- **Consequence:** won't fit on an MCU with 64 KB RAM.
- **Workaround:** reduce `COMPRESS_BUF` or make it dynamic.

### 6.3. `g_cache_arr[256]` — 512 bytes

- Cache of `pub^c` in `schnorr_verify_cfg` when `schnorr_cache = 1`.
- **Consequence:** 512 bytes globally; noticeable on AVR.
- **Workaround:** don't enable `--schnorr cache` on weak MCUs.

## 7. Tests and benchmarks

### 7.1. `test_algo` uses `clock()` for the seed

- Seed: `time ^ (pid << 16) ^ clock()`.
- **Consequence:** on a fast re-run the seed may coincide.
- **Workaround:** `getrandom()` for the seed.

### 7.2. `bench` measures CPU only

- `stream_xor`, `ks16`, `modpow` — no TCP, `read`/`write`, `select`.
- **Consequence:** `Mbps` in `bench` is an upper bound; real throughput
  is lower due to syscall/TCP overhead.
- **Workaround:** measure `run_file_tests.sh` with `time` for end-to-end throughput.

### 7.3. `run_file_tests.sh` — `sleep 0.3`

- Waits for the server to `bind`/`listen`.
- **Consequence:** on a slow machine the server may not be ready — the client gets
  `connect: Connection refused`.
- **Workaround:** a wait loop with `nc -z 127.0.0.1 $PORT` instead of `sleep`.

### 7.4. `run_file_tests.sh` — full matrix

- 3 kdf × 3 cipher × 3 compress × 2 auth × 3 prng × 2 mac × 2 schnorr × 2 dh = 1296
  combinations per file × 8 files ≈ 10,368 runs.
- **Consequence:** a full run takes hours.
- **Workaround:** OFAT matrix (one-factor-at-a-time): baseline + one deviation
  per option = 13 runs per file.

## 8. CLI and UX

### 8.1. No `--version`

- `PROTO_VERSION = 1` only in `proto.h`.
- **Workaround:** `grep PROTO_VERSION include/proto.h`.

### 8.2. No `--help` with return codes

- `usage()` prints the syntax but does not explain the values of `--kdf`/`--cipher`/...
- **Workaround:** read `docs/API.md`.

### 8.3. No config file

- All parameters via CLI.
- **Consequence:** long commands; no saved settings.
- **Workaround:** a shell script or a `Makefile` target.

### 8.4. `--dh test` is not forbidden in production

- `DH_TEST` restricts `a, b ∈ [1, 256]` — reduces DH strength even further.
- **Consequence:** accidentally using `--dh test` breaks security.
- **Workaround:** the server rejects `dh_mode == DH_TEST` unless `--allow-test` is set.

## 9. Process security

### 9.1. `authorized_keys` is read at startup

- Revoking a key requires a server restart.
- **Workaround:** re-read on `SIGHUP` or on every `accept`.

### 9.2. Logs contain `S` and keys

- `session_log(sess, "dh ok S=%04x", *S)` and `auth OK S=%04x`.
- **Consequence:** compromising the logs reveals `S` (and via `S` — the keystream).
- **Workaround:** don't log `S`, log only `hash(S)`.

### 9.3. No rate-limiting

- `accept` → immediate handshake; no flood protection.
- **Consequence:** DoS via many connections.
- **Workaround:** `SO_REUSEADDR` + concurrent session counter + `sleep` on error.

### 9.4. No handshake timeout

- `dh_client_cfg`/`dh_server_cfg` block on `read_full`.
- **Consequence:** a slow client holds the server.
- **Workaround:** `select` with a timeout before `read_full`, or `SO_RCVTIMEO`.

## 10. Compatibility

### 10.1. Linux/POSIX only

- `fork`, `execvp`, `socketpair`, `select`, `termios` (not used) — POSIX.
- **Consequence:** Windows requires WSL or a port to `CreateProcess`/`WSAPoll`.

### 10.2. `liblz4` is optional

- Without `liblz4-dev`, `lz4_compress_wrap` returns `-1`.
- **Consequence:** negotiation with `--compress lz4` fails if at least one side
  was built without `HAVE_LZ4`.
- **Workaround:** `sudo apt install liblz4-dev`; or use only `rle`.

### 10.3. 16-bit arithmetic

- `uint16_t` for `S`, `priv`, `pub`, `ctr`, `len`.
- **Consequence:** on 8-bit AVR (Uno/Nano) `uint32_t` multiplication is software, `modpow`
  ~2 ms; on ESP32 — faster.
- **Limitation:** `MAX_PAYLOAD=65535` and 128 KB `COMPRESS_BUF` don't fit in AVR.

## 11. Future work (not implemented)

| Feature | Complexity | Benefit |
|---|---|---|
| Server authentication | medium (~40 lines) | closes MITM |
| Re-keying | medium (~50 lines) | forward secrecy |
| 4-byte `flen` + blocks | low (~10 lines) | files up to 4 GB |
| `termios` raw + `SIGINT` | medium (~80 lines) | proper shell |
| MAC over `hash(S, ctr, ct)` | low | detects payload substitution |
| Range-based negotiation | medium | flexibility |
| Port forwarding | high (~150 lines) | like `ssh -L` |
| `SIGHUP` for `authorized_keys` | low | key revocation without restart |
| `getrandom()` for the seed | low | cryptographically strong PRNG |
| `--version` | trivial | UX |

## 12. Summary: what you can and cannot do

**You can:**
- Study the structure of DH + Schnorr + negotiation + stream cipher on integer
  arithmetic.
- Compare the `kdf`/`cipher`/`mac`/`prng`/`compress` variants in `bench` and `test_proto`.
- Transfer files ≤ 65535 bytes between two Linux machines.
- Use it as a foundation for an educational network security project.

**You cannot:**
- Protect real secrets.
- Use it in production.
- Rely on the MAC as payload integrity protection.
- Treat `S` as secret when traffic is recorded (16-bit DH is broken).
- Run on AVR/ESP32 without reducing `MAX_PAYLOAD`/`COMPRESS_BUF`.