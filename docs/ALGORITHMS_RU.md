# Algorithms

Все примитивы — над `GF(P)`, `P = 65519`, `P-1 = 65518 = 2·7·31·151`, `gcd(3, P-1) = 1`.
`G` — генератор `Z_P*`, вычисляется `find_generator()` (сейчас `11`).

## 1. `modpow`

```
result = 1; b = base mod P
while exp > 0:
    if exp & 1: result = (result * b) mod P
    b = (b * b) mod P
    exp >>= 1
return result
```

- Сложность: `O(log exp)` умножений; `exp < P` → ≤ 16 итераций, ≤ 32 умножений.
- Промежуточные значения — `uint32_t`, `P-1 < 2^16` → `(P-1)^2 < 2^32`, переполнения нет.
- Предельные: `exp=0 → 1`; `exp=P-1 → 1` (Ферма); `base=0 → 0`.

## 2. DH (Diffie–Hellman)

```
client: a ← random(1, P-2); A = G^a mod P; send (A, nonce_c[4])
server: b ← random(1, P-2); B = G^b mod P; send (B, nonce_s[4])
both:   S = peer_pub^own_priv mod P
```

- Функции: `dh_client_cfg`, `dh_server_cfg`, `modpow`, `prng_next`.
- Проверки: `A, B ∉ {0, 1, P-1}`; `A, B < P`.
- `DH_TEST` ограничивает `a, b ∈ [1, 256]` — только для бенчмарков.
- Стойкость: ~16 бит. BSGS: ~256 шагов, ~256 памяти → миллисекунды на ПК.

## 3. Schnorr

```
keygen: priv ← random(1, P-2); pub = G^priv mod P
prove:  r ← random(1, P-2); R = G^r mod P; s = (r + c·priv) mod (P-1)
verify: G^s mod P == R · pub^c mod P
```

- Функции: `schnorr_prove_cfg`, `schnorr_verify_cfg`, `auth_schnorr_server`, `auth_schnorr_client`.
- Challenge: `c = ks16_cfg(S, rnd) ^ 0xFFFF`, принудительно `c ≠ 0`.
- `schnorr_cache`: массив `pub^c` для `c ∈ [0, 255]`, инвалидация при смене `pub`.
- Completeness: 1000 случайных ключей в `test_algo` — все проходят.
- Soundness: 4 мутации (`c^1`, `R^1`, `s+1`, чужой `pub`) — все отвергаются.
- Предельные: `c=0` без принудительного `c≠0` пропускал бы без `priv`; `R=0` отвергается сервером.

## 4. HMAC-like auth (вариант)

```
client: tag = ks16_cfg(S, priv ^ c) → server
server: для каждого key: ks16_cfg(S, key ^ c) == tag ?
```

- Функции: `auth_hmac_server`, `auth_hmac_client`.
- Быстрее Schnorr (1 `ks16` против `modpow`), но offline-перебор `priv` тривиален.
- Только для сравнения, не для реальной защиты.

## 5. KDF `ks16`

```
ks16(S, ctr) = ((((S ^ ctr) | 1) mod P)^3) mod P
```

- Биекция по `x` при `gcd(3, P-1)=1`; обратная — `y^D_INV mod P`.
- `| 1` гарантирует ненулевой нечётный вход; побочный эффект — коллизия `(c, c^1)` при чётном `S^c`, вероятность `~1/32768` на случайную пару.
- Варианты:
  - `KDF_BYTE`: `(S ^ ctr) & 0xFF` — один байт, слабый.
  - `KDF_CUBE`: базовый.
  - `KDF_DOUBLE`: `ks16(ks16(S, ctr), ctr ^ 0xAAAA)` — лучше перемешивает.
- Функции: `ks16`, `ks16_cfg`, `ks_byte_cfg`.

## 6. Потоковый шифр

```
ks_byte(S, ctr, i) = fold(ks16_cfg(S, ctr + i))
C[i] = P[i] ^ keystream[i]
```

- `fold(v) = v ^ (v >> 8) & 0xFF`.
- Варианты:
  - `CIPHER_KS16`: один `ks16` на байт.
  - `CIPHER_RAW`: младший байт `ks16_cfg` без fold.
  - `CIPHER_BLOCK`: один `ks16` на 2 байта (младший → чётный, старший → нечётный).
- Инволюция: `stream_xor(stream_xor(x)) == x` (XOR).
- Функции: `stream_xor_cfg`, `ks_byte_cfg`.

## 7. MAC пакета

```
tag = ks16_cfg(S, ctr ^ 0xFFFF)   // 2 байта
```

- Зависит от `S` и `ctr`, **не** от payload.
- Защищает от: replay (другой `ctr` → другой `tag`), перестановки, потери.
- Не защищает от: подмены ciphertext внутри сессии.
- Коллизия `tag(0) = tag(0xFFFF)` — переполнение `ctr` за сессию маловероятно, но возможно при длинной сессии.
- Функции: `mac_cfg`.

## 8. PRNG

```
x ^= x << 13; x ^= x >> 17; x ^= x << 5
```

- Варианты:
  - `PRNG_XORSHIFT`: как есть.
  - `PRNG_MASK`: `return x & 0xFFFF` — 16-бит.
  - `PRNG_CLOCK`: `state ^= clock()` перед шагом — дешёвая недетерминированность.
- Не криптостойкий: предсказуем при известном seed (`time ^ pid ^ clock`).
- Функции: `prng_next`.

## 9. Компрессия

- `RLE`: пары `(run:1, value:1)`, `run ≤ 255`. На случайных данных **расширяет** вход.
- `LZ4`: `LZ4_compress_default`/`LZ4_decompress_safe` при `HAVE_LZ4`; иначе `-1`.
- Семантика SSH: сжатый payload передаётся **всегда**, даже если он больше исходного; получатель всегда распаковывает при `compress_mode != COMPRESS_NONE`.
- Функции: `rle_compress/decompress`, `lz4_compress_wrap/lz4_decompress_wrap`, `compress_buf/decompress_buf`.

## 10. Сводка вариантов

| Примитив | Варианты | Функция-диспетчер |
|---|---|---|
| DH | `normal`, `test` | `dh_client_cfg`, `dh_server_cfg` |
| Auth | `schnorr`, `hmac` | `auth_*_server/client` |
| Schnorr cache | `plain`, `cache` | `schnorr_verify_cfg` |
| KDF | `cube`, `byte`, `double` | `ks16_cfg` |
| Cipher | `ks16`, `raw`, `block` | `stream_xor_cfg` |
| MAC | `ks16`, `precalc` | `mac_cfg` |
| PRNG | `xorshift`, `mask`, `clock` | `prng_next` |
| Compression | `none`, `rle`, `lz4` | `compress_buf/decompress_buf` |

`MAC_PRECALC` в текущей реализации идентичен `MAC_KS16` — задел на буферизацию тегов вперёд.

## 11. Ограничения и почему это «игрушка»

- 16-битный DH ломается BSGS за миллисекунды.
- `x^3 mod P` обратим при известном `D_INV`, который публичен.
- MAC не покрывает данные.
- PRNG не криптостойкий.
- Нет аутентификации сервера — MITM подменяет `B`.
- Нет forward secrecy: компрометация `priv` или перебор `a` раскрывает `S`.
