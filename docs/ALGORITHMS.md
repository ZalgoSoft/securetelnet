# Algorithms

All primitives are over `GF(P)`, `P = 65519`, `P-1 = 65518 = 2·7·31·151`, `gcd(3, P-1) = 1`.
`G` is a generator of `Z_P*`, computed by `find_generator()` (currently `11`).

## 1. `modpow`

```
result = 1; b = base mod P
while exp > 0:
    if exp & 1: result = (result * b) mod P
    b = (b * b) mod P
    exp >>= 1
return result
```

- Complexity: `O(log exp)` multiplications; `exp < P` → ≤ 16 iterations, ≤ 32 multiplications.
- Intermediate values are `uint32_t`, `P-1 < 2^16` → `(P-1)^2 < 2^32`, no overflow.
- Edge cases: `exp=0 → 1`; `exp=P-1 → 1` (Fermat); `base=0 → 0`.

## 2. DH (Diffie–Hellman)

```
client: a ← random(1, P-2); A = G^a mod P; send (A, nonce_c[4])
server: b ← random(1, P-2); B = G^b mod P; send (B, nonce_s[4])
both:   S = peer_pub^own_priv mod P
```

- Functions: `dh_client_cfg`, `dh_server_cfg`, `modpow`, `prng_next`.
- Checks: `A, B ∉ {0, 1, P-1}`; `A, B < P`.
- `DH_TEST` restricts `a, b ∈ [1, 256]` — benchmarks only.
- Strength: ~16 bits. BSGS: ~256 steps, ~256 memory → milliseconds on a PC.

## 3. Schnorr

```
keygen: priv ← random(1, P-2); pub = G^priv mod P
prove:  r ← random(1, P-2); R = G^r mod P; s = (r + c·priv) mod (P-1)
verify: G^s mod P == R · pub^c mod P
```

- Functions: `schnorr_prove_cfg`, `schnorr_verify_cfg`, `auth_schnorr_server`, `auth_schnorr_client`.
- Challenge: `c = ks16_cfg(S, rnd) ^ 0xFFFF`, forcibly `c ≠ 0`.
- `schnorr_cache`: array of `pub^c` for `c ∈ [0, 255]`, invalidated when `pub` changes.
- Completeness: 1000 random keys in `test_algo` — all pass.
- Soundness: 4 mutations (`c^1`, `R^1`, `s+1`, someone else's `pub`) — all rejected.
- Edge cases: `c=0` without forcing `c≠0` would pass without `priv`; `R=0` is rejected by the server.

## 4. HMAC-like auth (variant)

```
client: tag = ks16_cfg(S, priv ^ c) → server
server: for each key: ks16_cfg(S, key ^ c) == tag ?
```

- Functions: `auth_hmac_server`, `auth_hmac_client`.
- Faster than Schnorr (1 `ks16` vs `modpow`), but offline brute-forcing of `priv` is trivial.
- For comparison only, not for real protection.

## 5. KDF `ks16`

```
ks16(S, ctr) = ((((S ^ ctr) | 1) mod P)^3) mod P
```

- Bijection in `x` when `gcd(3, P-1)=1`; the inverse is `y^D_INV mod P`.
- `| 1` guarantees a nonzero odd input; a side effect is the `(c, c^1)` collision when `S^c` is even, probability `~1/32768` per random pair.
- Variants:
  - `KDF_BYTE`: `(S ^ ctr) & 0xFF` — one byte, weak.
  - `KDF_CUBE`: baseline.
  - `KDF_DOUBLE`: `ks16(ks16(S, ctr), ctr ^ 0xAAAA)` — mixes better.
- Functions: `ks16`, `ks16_cfg`, `ks_byte_cfg`.

## 6. Stream cipher

```
ks_byte(S, ctr, i) = fold(ks16_cfg(S, ctr + i))
C[i] = P[i] ^ keystream[i]
```

- `fold(v) = v ^ (v >> 8) & 0xFF`.
- Variants:
  - `CIPHER_KS16`: one `ks16` per byte.
  - `CIPHER_RAW`: low byte of `ks16_cfg` without fold.
  - `CIPHER_BLOCK`: one `ks16` per 2 bytes (low → even, high → odd).
- Involution: `stream_xor(stream_xor(x)) == x` (XOR).
- Functions: `stream_xor_cfg`, `ks_byte_cfg`.

## 7. Packet MAC

```
tag = ks16_cfg(S, ctr ^ 0xFFFF)   // 2 bytes
```

- Depends on `S` and `ctr`, **not** on the payload.
- Protects against: replay (different `ctr` → different `tag`), reordering, loss.
- Does not protect against: ciphertext substitution within a session.
- Collision `tag(0) = tag(0xFFFF)` — `ctr` overflow within a session is unlikely, but possible for a long session.
- Functions: `mac_cfg`.

## 8. PRNG

```
x ^= x << 13; x ^= x >> 17; x ^= x << 5
```

- Variants:
  - `PRNG_XORSHIFT`: as is.
  - `PRNG_MASK`: `return x & 0xFFFF` — 16-bit.
  - `PRNG_CLOCK`: `state ^= clock()` before the step — cheap nondeterminism.
- Not cryptographically strong: predictable given the seed (`time ^ pid ^ clock`).
- Functions: `prng_next`.

## 9. Compression

- `RLE`: pairs `(run:1, value:1)`, `run ≤ 255`. On random data it **expands** the input.
- `LZ4`: `LZ4_compress_default`/`LZ4_decompress_safe` when `HAVE_LZ4`; otherwise `-1`.
- SSH semantics: the compressed payload is **always** transmitted, even if it is larger than the original; the recipient always decompresses when `compress_mode != COMPRESS_NONE`.
- Functions: `rle_compress/decompress`, `lz4_compress_wrap/lz4_decompress_wrap`, `compress_buf/decompress_buf`.

## 10. Variant summary

| Primitive | Variants | Dispatcher function |
|---|---|---|
| DH | `normal`, `test` | `dh_client_cfg`, `dh_server_cfg` |
| Auth | `schnorr`, `hmac` | `auth_*_server/client` |
| Schnorr cache | `plain`, `cache` | `schnorr_verify_cfg` |
| KDF | `cube`, `byte`, `double` | `ks16_cfg` |
| Cipher | `ks16`, `raw`, `block` | `stream_xor_cfg` |
| MAC | `ks16`, `precalc` | `mac_cfg` |
| PRNG | `xorshift`, `mask`, `clock` | `prng_next` |
| Compression | `none`, `rle`, `lz4` | `compress_buf/decompress_buf` |

In the current implementation `MAC_PRECALC` is identical to `MAC_KS16` — future work for buffering tags ahead.

## 11. Limitations and why this is a "toy"

- 16-bit DH is broken by BSGS in milliseconds.
- `x^3 mod P` is invertible given the public `D_INV`.
- The MAC does not cover the data.
- The PRNG is not cryptographically strong.
- No server authentication — a MITM substitutes `B`.
- No forward secrecy: compromising `priv` or brute-forcing `a` reveals `S`.
