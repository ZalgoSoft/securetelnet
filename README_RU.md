# securetelnet

Учебный протокол защищённого обмена сообщениями и файлами поверх TCP.
Только 16-битная целочисленная арифметика, без внешних криптобиблиотек
(опционально — `liblz4` для LZ4-сжатия).

## Возможности

- DH-обмен ключами (16-бит, игрушечный, но структурно правильный).
- Аутентификация клиента по ключу: Schnorr или упрощённый HMAC-like.
- KDF на `x^3 mod P`, потоковый XOR-шифр, MAC на пакет.
- Согласование алгоритмов (negotiation) до handshake.
- Режимы: `chat`, `shell`, `file`.
- Компрессия: `none`, `rle`, `lz4` (опционально).
- Сессионный лог, keepalive, таймаут.
- File-mode: `put`/`get`, sandbox (`path_is_safe`), `--overwrite`/авто-`file.N`.

## Сборка

```bash
make                # securetelnet + test_algo + test_proto + bench
make test           # юнит- и протокольные тесты
make bench          # нагрузочные тесты
sudo apt install liblz4-dev   # опционально, для LZ4
```

## Быстрый старт

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

## Документация

- [`docs/API.md`](docs/API.md) — все функции, структуры, константы.
- [`docs/ALGORITHMS.md`](docs/ALGORITHMS.md) — примитивы и их варианты.
- [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — wire-format и последовательности.
- [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) — известные ограничения и заделы.

## Ограничения

- Стойкость DH — ~16 бит. Перебор `a` по `A = G^a mod P` — миллисекунды на ПК.
- `ks16` — не криптостойкая OWF: `x^3 mod P` обратим при известном `D_INV`.
- MAC не привязан к plaintext/ciphertext — защищает от replay/перестановки, но не от подмены внутри сессии.
- Нет аутентификации сервера — MITM может подменить `B`.
- PRNG `xorshift32` не криптостойкий.
- `MAX_PAYLOAD = 65535`, файлы > 64 КБ требуют 4-байтового размера и блочной передачи (см. `docs/PROTOCOL.md`, раздел «File transfer extensions»).

Проект предназначен для изучения структуры DH + Schnorr + потокового шифра + negotiation, а не для защиты реальных секретов.
