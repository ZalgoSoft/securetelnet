CC=gcc
CFLAGS=-O2 -Wall -Wextra -Iinclude -Isrc -std=c99
LZ4_CFLAGS=$(shell pkg-config --cflags liblz4 2>/dev/null)
LZ4_LIBS=$(shell pkg-config --libs liblz4 2>/dev/null)
HAVE_LZ4=$(shell pkg-config --exists liblz4 && echo 1)

ifeq ($(HAVE_LZ4),1)
CFLAGS += -DHAVE_LZ4 $(LZ4_CFLAGS)
endif

LIBS=libio.a libcrypto.a libcompress.a libnegotiation.a libproto.a libsession.a liblog.a libmode.a libapp.a

all: securetelnet tests bench

libio.a: src/io/io.o
	ar rcs $@ $^

libcrypto.a: src/crypto/field.o src/crypto/context.o src/crypto/dh_normal.o src/crypto/dh_test.o \
             src/crypto/dh_registry.o src/crypto/kdf_cube.o src/crypto/kdf_byte.o src/crypto/kdf_double.o \
             src/crypto/kdf_registry.o src/crypto/cipher_ks16.o src/crypto/cipher_raw.o src/crypto/cipher_block.o \
             src/crypto/cipher_registry.o src/crypto/mac_ks16.o src/crypto/mac_precalc.o src/crypto/mac_registry.o \
             src/crypto/prng_xorshift.o src/crypto/prng_mask.o src/crypto/prng_clock.o src/crypto/prng_registry.o \
             src/crypto/auth_schnorr.o src/crypto/auth_hmac.o src/crypto/auth_registry.o
	ar rcs $@ $^

libcompress.a: src/compress/compress_none.o src/compress/compress_rle.o src/compress/compress_lz4.o src/compress/compress_registry.o
	ar rcs $@ $^

libnegotiation.a: src/negotiation/negotiation.o
	ar rcs $@ $^

libproto.a: src/proto/proto.o
	ar rcs $@ $^

libsession.a: src/session/session.o
	ar rcs $@ $^

liblog.a: src/log/log.o
	ar rcs $@ $^

libmode.a: src/mode/mode.o src/mode/mode_chat.o src/mode/mode_shell.o src/mode/mode_file/mode_file.o \
           src/mode/mode_file/path_safe.o src/mode/mode_file/pick_name.o src/mode/mode_file/transfer.o
	ar rcs $@ $^

libapp.a: src/app/app_server.o src/app/app_client.o src/app/app_keygen.o
	ar rcs $@ $^

securetelnet: src/main.o $(LIBS)
	$(CC) $(CFLAGS) -o $@ src/main.o libapp.a libmode.a libsession.a liblog.a libproto.a libnegotiation.a libcompress.a libcrypto.a libio.a $(LZ4_LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

tests: test_io test_crypto test_compress test_negotiation test_proto test_session test_mode_file test_help

test_io: tests/test_io.o libio.a
	$(CC) $(CFLAGS) -o $@ $^ $(LZ4_LIBS)

test_crypto: tests/test_crypto.o libcrypto.a libio.a
	$(CC) $(CFLAGS) -o $@ $^ $(LZ4_LIBS)

test_compress: tests/test_compress.o libcompress.a
	$(CC) $(CFLAGS) -o $@ $^ $(LZ4_LIBS)

test_negotiation: tests/test_negotiation.o libnegotiation.a libio.a
	$(CC) $(CFLAGS) -o $@ $^ $(LZ4_LIBS)

test_proto: tests/test_proto.o libproto.a libcrypto.a libcompress.a libio.a
	$(CC) $(CFLAGS) -o $@ $^ $(LZ4_LIBS)

test_session: tests/test_session.o libsession.a liblog.a
	$(CC) $(CFLAGS) -o $@ $^ $(LZ4_LIBS)

test_mode_file: tests/test_mode_file.o libmode.a libproto.a libsession.a libcrypto.a libcompress.a liblog.a libio.a
	$(CC) $(CFLAGS) -o $@ $^ $(LZ4_LIBS)

test_help: tests/test_help.o libcrypto.a libcompress.a libio.a
	$(CC) $(CFLAGS) -o $@ $^ $(LZ4_LIBS)

bench: bench_crypto bench_compress

bench_crypto: tests/bench_crypto.o libcrypto.a libio.a
	$(CC) $(CFLAGS) -o $@ $^ $(LZ4_LIBS)

bench_compress: tests/bench_compress.o libcompress.a
	$(CC) $(CFLAGS) -o $@ $^ $(LZ4_LIBS)

clean:
	rm -f $(LIBS) securetelnet test_io test_crypto test_compress test_negotiation test_proto test_session test_mode_file test_help bench_crypto bench_compress
	find src tests -name '*.o' -delete

.PHONY: all clean tests bench
