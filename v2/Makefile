CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -Iinclude
LDFLAGS =

LZ4_CFLAGS := $(shell pkg-config --cflags liblz4 2>/dev/null)
LZ4_LIBS   := $(shell pkg-config --libs liblz4 2>/dev/null)
ifneq ($(LZ4_CFLAGS)$(LZ4_LIBS),)
CFLAGS  += $(LZ4_CFLAGS) -DHAVE_LZ4
LDLIBS  += $(LZ4_LIBS)
endif

SRC = src/algo.c src/proto.c src/compress_rle.c src/compress_lz4.c \
      src/session.c src/keygen.c src/server.c src/client.c src/main.c
OBJ = $(SRC:.c=.o)
TARGET = securetelnet

TEST_ALGO_SRC  = tests/test_algo.c src/algo.c
TEST_PROTO_SRC = tests/test_proto.c src/algo.c src/proto.c src/compress_rle.c src/compress_lz4.c
BENCH_SRC      = tests/bench.c src/algo.c src/proto.c src/compress_rle.c src/compress_lz4.c

.PHONY: all test test-algo test-proto bench clean

all: $(TARGET) test_algo test_proto bench

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test_algo: $(TEST_ALGO_SRC)
	$(CC) $(CFLAGS) $(TEST_ALGO_SRC) -o $@ $(LDFLAGS) $(LDLIBS)

test_proto: $(TEST_PROTO_SRC)
	$(CC) $(CFLAGS) $(TEST_PROTO_SRC) -o $@ $(LDFLAGS) $(LDLIBS)

bench: $(BENCH_SRC)
	$(CC) $(CFLAGS) $(BENCH_SRC) -o $@ $(LDFLAGS) $(LDLIBS)

test: test_algo test_proto
	./test_algo
	./test_proto

clean:
	rm -f $(OBJ) $(TARGET) test_algo test_proto bench
