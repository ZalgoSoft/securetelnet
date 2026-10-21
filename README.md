# securetelnet

An educational protocol for secure message and file exchange over TCP.
Only 16-bit integer arithmetic, no external crypto libraries
(optionally — `liblz4` for LZ4 compression).

## Features

- DH key exchange (16-bit, toy-grade but structurally correct).
- Client authentication by key: Schnorr or simplified HMAC-like.
- KDF on `x^3 mod P`, stream XOR cipher, per-packet MAC.
- Algorithm negotiation before the handshake.
- Modes: `chat`, `shell`, `file`.
- Compression: `none`, `rle`, `lz4` (optional).
- Session log, keepalive, timeout.
- File mode: `put`/`get`, sandbox (`path_is_safe`), `--overwrite`/auto-`file.N`.

## Build

```bash
make                # securetelnet + test_algo + test_proto + bench
make test           # unit and protocol tests
make bench          # load tests
sudo apt install liblz4-dev   # optional, for LZ4
```

## Quick start

```bash
./securetelnet keygen client.priv client.pub
cp client.pub authorized_keys

# chat
./securetelnet server 5555 authorized_keys --mode chat --session-dir logs
./securetelnet client 127.0.0.1 5555 client.priv --mode chat --session-dir logs

# shell
./securetelnet server 5556 authorized_keys --mode shell --shell /bin/bash
./securetelnet client 127.0.0.1 5556 client.priv --mode shell

# file
./securetelnet server 5557 authorized_keys --mode file --overwrite
./securetelnet client 127.0.0.1 5557 client.priv --mode file \
    --file-cmd 'put tests/out/f32768.bin tests/in/f32768.up.bin'
./securetelnet client 127.0.0.1 5557 client.priv --mode file \
    --file-cmd 'get tests/in/f32768.up.bin tests/in/f32768.down.bin'
```

## Documentation

- [`docs/API.md`](docs/API.md) — all functions, structures, constants.
- [`docs/ALGORITHMS.md`](docs/ALGORITHMS.md) — primitives and their variants.
- [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — wire format and sequences.
- [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) — known limitations and future work.

## Limitations

- DH strength is ~16 bits. Brute-forcing `a` from `A = G^a mod P` takes milliseconds on a PC.
- `ks16` is not a cryptographically strong OWF: `x^3 mod P` is invertible given `D_INV`.
- The MAC is not bound to the plaintext/ciphertext — it protects against replay/reordering, but not against substitution within a session.
- There is no server authentication — a MITM can substitute `B`.
- The `xorshift32` PRNG is not cryptographically secure.
- `MAX_PAYLOAD = 65535`; files larger than 64 KB require a 4-byte size and block-based transfer (see `docs/PROTOCOL.md`, section "File transfer extensions").

The project is intended for studying the structure of DH + Schnorr + stream cipher + negotiation, not for protecting real secrets.
