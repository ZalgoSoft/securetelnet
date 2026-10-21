./test_algo
tests: seed=8fceab84 G=11
test modpow seed=8fceab84
  G=11 P=65519
  OK exp0
  OK exp1
  OK Fermat
test DH seed=8fceab84
  pairs=1000 bad=0 seed_after=5a4cc58a
test Schnorr seed=8fceab84
  keys=1000 bad=0 seed_after=3ed33aca
  mutations=4 accepted=0 seed_after=5ec30196 (saved=1)
test ks16 seed=8fceab84
  S1=ab84 S2=ddbb c1=0d3f c2=98b5
  OK determ/diff
  collision pairs=4096 observed=0 expected~0.062 seed_after=3bd8d1fd
test stream_xor seed=8fceab84
  ks16       S=ab84 ctr=ddbb len=64 ok=1
  raw        S=0d3f ctr=98b5 len=64 ok=1
  block      S=7879 ctr=09e3 len=64 ok=1
  kdf_byte   S=ff44 ctr=6687 len=64 ok=1
  kdf_double S=e67e ctr=19ad len=64 ok=1
  seed_after=05008e95
test prng seed=8fceab84
  xorshift=0d7eddbb mask=0000ddbb mask<=0xffff=1
test auth_hmac seed=8fceab84
  S=98b5 priv=ddbb c=1234 tag=b72c
  match key[1]=ddbb
  OK
ALL TESTS OK

./test_proto
tests: seed=8fc1aa31 G=11
test compress seed=8fc1aa31
  none in=256 out=256 ok=1
  rle  in=256 out=4 ok=1
  lz4  in=256 out=11 ok=1
  seed_after=ea7d3932
test negotiate ok seed=ea7d3932
  client_r=0 kdf=0 compress=1 server_exit=0 ok=1
test negotiate mismatch seed=e630ac7f
  client_r=-1 server_exit=1 ok=1
test packet roundtrips seed=845981a0
  cube/ks16/none       kdf=0 cipher=0 comp=0 len=64 ok=1
  cube/raw/none        kdf=0 cipher=1 comp=0 len=50 ok=1
  cube/block/none      kdf=0 cipher=2 comp=0 len=78 ok=1
  byte/ks16/none       kdf=1 cipher=0 comp=0 len=76 ok=1
  double/ks16/none     kdf=2 cipher=0 comp=0 len=29 ok=1
  byte/ks16/rle        kdf=1 cipher=0 comp=1 len=64 ok=1
  double/ks16/rle      kdf=2 cipher=0 comp=1 len=8 ok=1
  cube/ks16/rle        kdf=0 cipher=0 comp=1 len=85 ok=1
  byte/ks16/lz4        kdf=1 cipher=0 comp=2 len=69 ok=1
  double/ks16/lz4      kdf=2 cipher=0 comp=2 len=80 ok=1
  cube/ks16/lz4        kdf=0 cipher=0 comp=2 len=18 ok=1
  seed_after=0d602bc1
ALL TESTS OK

./bench
bench: seed=8ff1aa13 G=11
---------------------------------------------------------------
modpow           n=200000  0.029s   6843765.8 ops/s      0.15 us/op
ks16 (cube)      n=2000000 0.028s  71684574.9 ops/s      0.01 us/op  acc=36985
stream_xor ks16   len=64    n=200000  0.148s   1346870.9 pkt/s    689.60 Mbps
stream_xor raw    len=64    n=200000  0.136s   1472678.1 pkt/s    754.01 Mbps
stream_xor block  len=64    n=200000  0.076s   2621968.2 pkt/s   1342.45 Mbps
stream_xor ks16   len=1024  n=20000   0.225s     88833.3 pkt/s    727.72 Mbps
schnorr prove+ver n=20000   0.012s   1719423.2 ops/s      0.58 us/op  ok=20000
schnorr+cat cache n=20000   0.006s   3282740.8 ops/s      0.30 us/op  ok=20000
prng xorshift    n=5000000 0.024s  207084870.3 ops/s      4.83 ns/op  acc=05e3db0e
compress rle     n=200000  0.098s   2031429.0 ops/s      0.49 us/op  avg_out=128
compress lz4     n=200000  0.252s    793876.0 ops/s      1.26 us/op  avg_out=258
packet proc len=64    n=200000  0.149s   1344070.1 pkt/s    688.16 Mbps
packet proc len=1024  n=20000   0.231s     86728.1 pkt/s    710.48 Mbps
---------------------------------------------------------------
bench done, seed_after=6662c2c4

./securetelnet
usage:
  ./securetelnet keygen <privfile> <pubfile>
  ./securetelnet server <port> <authorized_keys> [--mode chat|shell|file] [--shell /bin/sh]
       [--kdf cube|byte|double] [--cipher ks16|raw|block]
       [--auth schnorr|hmac] [--schnorr plain|cache]
       [--mac ks16|precalc] [--prng xorshift|mask|clock]
       [--compress none|rle|lz4] [--dh normal|test] [--session-dir DIR]
  ./securetelnet client <host> <port> <privfile> [--mode chat|shell|file] [--file-cmd 'get path'|'put path']
       [--kdf ...] [--cipher ...] [--auth ...] [--schnorr ...]
       [--mac ...] [--prng ...] [--compress ...] [--dh ...] [--session-dir DIR]


usage: ./tests/run_file_tests.sh [--size N] [--compress X] [--no-overwrite]

./tests/run_file_tests.sh
=== generating keys ===
=== generating test files ===
=== files in securetelnet/v2/tests/out ===
  f0.bin size=0 sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  f1.bin size=1 sha256=684888c0ebb17f374298b65ee2807526c066094c701bcc7ebbe1c1095f494fc1
  f2.bin size=2 sha256=1a3664edd88de516e2a1f695648fdd2af44f14dd1327b3e9f497780e529b0051
  f32768.bin size=32768 sha256=bc6ec1d3b9e44043e5906b797878ebe0a217f6a39a2ae1072f7a0005329105d5
  f32769.bin size=32769 sha256=d18a38e830ba5afd0d47a30d6a17232cd11b4137596e4a145615c84d24225e38
  f65535.bin size=65535 sha256=79255c2a021ae6a0fd0af4528d39ced06ae3264f02d08db1a5962d477315cab9
  f65536.bin size=65536 sha256=86d236164c5f9b9027a3fa8cec04030ecd88e91c3d5967127fd18494cd798a0a
  f1048576.bin size=1048576 sha256=1b3b353020c15d7e0348dce3164bbae6edbba5bdd8165ad82c8777f331de14be
=== running matrix ===
-- put f0 size=0 kdf=cube cipher=ks16 compress=none auth=schnorr prng=xorshift mac=ks16 schnorr=plain dh=normal
   server: ./securetelnet server 62001 tests/keys/authorized_keys --mode file --overwrite --kdf cube --cipher ks16 --compress none --auth schnorr --prng xorshift --mac ks16 --schnorr plain --dh normal
   client: ./securetelnet client 127.0.0.1 62001 tests/keys/client.priv --mode file --file-cmd 'put out/f0.bin in/f0.up.cube_ks16_none_schnorr_xorshift_ks16_plain_normal.bin' --kdf cube --cipher ks16 --compress none --auth schnorr --prng xorshift --mac ks16 --schnorr plain --dh normal
   FAIL put f0 cube/ks16/none/schnorr/xorshift/ks16/plain/normal
-- put f0 size=0 kdf=cube cipher=ks16 compress=none auth=schnorr prng=xorshift mac=ks16 schnorr=plain dh=test
   server: ./securetelnet server 62002 tests/keys/authorized_keys --mode file --overwrite --kdf cube --cipher ks16 --compress none --auth schnorr --prng xorshift --mac ks16 --schnorr plain --dh test
   client: ./securetelnet client 127.0.0.1 62002 tests/keys/client.priv --mode file --file-cmd 'put out/f0.bin in/f0.up.cube_ks16_none_schnorr_xorshift_ks16_plain_test.bin' --kdf cube --cipher ks16 --compress none --auth schnorr --prng xorshift --mac ks16 --schnorr plain --dh test
   FAIL put f0 cube/ks16/none/schnorr/xorshift/ks16/plain/test
-- put f0 size=0 kdf=cube cipher=ks16 compress=none auth=schnorr prng=xorshift mac=ks16 schnorr=cache dh=normal
   server: ./securetelnet server 62003 tests/keys/authorized_keys --mode file --overwrite --kdf cube --cipher ks16 --compress none --auth schnorr --prng xorshift --mac ks16 --schnorr cache --dh normal
   client: ./securetelnet client 127.0.0.1 62003 tests/keys/client.priv --mode file --file-cmd 'put out/f0.bin in/f0.up.cube_ks16_none_schnorr_xorshift_ks16_cache_normal.bin' --kdf cube --cipher ks16 --compress none --auth schnorr --prng xorshift --mac ks16 --schnorr cache --dh normal
   FAIL put f0 cube/ks16/none/schnorr/xorshift/ks16/cache/normal
-- put f0 size=0 kdf=cube cipher=ks16 compress=none auth=schnorr prng=xorshift mac=ks16 schnorr=cache dh=test
   server: ./securetelnet server 62004 tests/keys/authorized_keys --mode file --overwrite --kdf cube --cipher ks16 --compress none --auth schnorr --prng xorshift --mac ks16 --schnorr cache --dh test
   client: ./securetelnet client 127.0.0.1 62004 tests/keys/client.priv --mode file --file-cmd 'put out/f0.bin in/f0.up.cube_ks16_none_schnorr_xorshift_ks16_cache_test.bin' --kdf cube --cipher ks16 --compress none --auth schnorr --prng xorshift --mac ks16 --schnorr cache --dh test


