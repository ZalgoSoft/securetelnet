#!/bin/bash
SIZES=(0 1 65536 1048576 10485760)
FILL=(random zeros)
COMPRESS=(none rle lz4)
CIPHERS=(ks16 raw block)
KDFS=(cube byte double)
NO_OVERWRITE=0
SHOW_CMDS=0
FILTER_SIZE=""
FILTER_COMPRESS=""
FILTER_CIPHER=""
FILTER_KDF=""

while [ $# -gt 0 ]; do
  case "$1" in
    --size) FILTER_SIZE="$2"; shift 2;;
    --compress) FILTER_COMPRESS="$2"; shift 2;;
    --cipher) FILTER_CIPHER="$2"; shift 2;;
    --kdf) FILTER_KDF="$2"; shift 2;;
    --no-overwrite) NO_OVERWRITE=1; shift;;
    --show-cmds) SHOW_CMDS=1; shift;;
    *) echo "unknown option: $1"; exit 1;;
  esac
done

OUT=tests/out
IN=tests/in
mkdir -p "$OUT" "$IN"

if [ ! -x ./securetelnet ]; then
  make securetelnet || exit 1
fi

if [ ! -f tests/server_priv ] || [ ! -f tests/server_pub ]; then
  ./securetelnet keygen tests/server_priv tests/server_pub
fi

PASS=0; FAIL=0; SKIP=0
PORT=23456

make_src() {
  local sz="$1" fill="$2" path="$3"
  if [ "$fill" = "zeros" ]; then
    head -c "$sz" /dev/zero > "$path"
  else
    head -c "$sz" /dev/urandom > "$path"
  fi
}

short_md5() {
  local h
  h=$(md5sum "$1" | awk '{print $1}')
  echo "${h:0:8}"
}

for sz in "${SIZES[@]}"; do
  if [ -n "$FILTER_SIZE" ] && [ "$sz" != "$FILTER_SIZE" ]; then continue; fi
  for fill in "${FILL[@]}"; do
    for cmp in "${COMPRESS[@]}"; do
      if [ -n "$FILTER_COMPRESS" ] && [ "$cmp" != "$FILTER_COMPRESS" ]; then continue; fi
      for ciph in "${CIPHERS[@]}"; do
        if [ -n "$FILTER_CIPHER" ] && [ "$ciph" != "$FILTER_CIPHER" ]; then continue; fi
        for kdf in "${KDFS[@]}"; do
          if [ -n "$FILTER_KDF" ] && [ "$kdf" != "$FILTER_KDF" ]; then continue; fi

          if [ "$cmp" = "lz4" ]; then
            if ! ./securetelnet --help 2>/dev/null | grep -qw lz4; then
              echo "SKIP: size=$sz fill=$fill compress=lz4 kdf=$kdf cipher=$ciph (not compiled in)"
              SKIP=$((SKIP+1))
              continue
            fi
          fi

          src="$OUT/src_${sz}_${fill}"
          make_src "$sz" "$fill" "$src"
          upname="upload_${sz}_${fill}_${cmp}_${ciph}_${kdf}_$$"

          srv_extra=""
          [ "$NO_OVERWRITE" = 1 ] && srv_extra="--no-overwrite"

          srv_cmd="./securetelnet server $PORT tests/server_pub --mode file --compress $cmp --cipher $ciph --kdf $kdf --dh test --allow-test --session-dir $OUT $srv_extra"
          cli_cmd="./securetelnet client 127.0.0.1 $PORT tests/server_priv --mode file --compress $cmp --cipher $ciph --kdf $kdf --dh test --file-cmd \"put $src $upname\""
          [ "$SHOW_CMDS" = 1 ] && { echo "SRV: $srv_cmd"; echo "CLI: $cli_cmd"; }

          eval "$srv_cmd" >/dev/null 2>&1 &
          SPID=$!
          sleep 0.2

          t0=$(date +%s.%N)
          CLI_OUT=$(eval "$cli_cmd" 2>&1)
          CLI_RC=$?
          t1=$(date +%s.%N)

          wait $SPID 2>/dev/null
          SRV_RC=$?

          elapsed=$(awk -v a="$t0" -v b="$t1" 'BEGIN{ printf "%.6f", b-a }')
          if [ "$sz" -gt 0 ]; then
            rate=$(awk -v s="$sz" -v t="$elapsed" 'BEGIN{ if (t>0) printf "%.2f", (s/1024.0)/t; else print "inf" }')
          else
            rate="n/a"
          fi

          if [ "$CLI_RC" -ne 0 ] || [ "$SRV_RC" -ne 0 ]; then
            echo "FAIL: size=$sz fill=$fill compress=$cmp cipher=$ciph kdf=$kdf client_rc=$CLI_RC server_rc=$SRV_RC elapsed=${elapsed}s"
            echo "  client output: $CLI_OUT"
            FAIL=$((FAIL+1))
            continue
          fi

          if [ ! -f "$upname" ]; then
            echo "FAIL: size=$sz fill=$fill compress=$cmp cipher=$ciph kdf=$kdf upload missing (client_rc=$CLI_RC server_rc=$SRV_RC elapsed=${elapsed}s)"
            FAIL=$((FAIL+1))
            continue
          fi

          m1=$(short_md5 "$src")
          m2=$(short_md5 "$upname")
          s1=$(stat -c %s "$src")
          s2=$(stat -c %s "$upname")
          if [ "$m1" = "$m2" ] && [ "$s1" = "$s2" ]; then
            echo "PASS: size=$sz fill=$fill compress=$cmp cipher=$ciph kdf=$kdf md5=$m1 bytes=$s1 elapsed=${elapsed}s rate=${rate}KiB/s"
            PASS=$((PASS+1))
          else
            echo "FAIL: size=$sz fill=$fill compress=$cmp cipher=$ciph kdf=$kdf md5_mismatch src=$m1 up=$m2 sizes=${s1}/${s2} elapsed=${elapsed}s"
            FAIL=$((FAIL+1))
          fi
        done
      done
    done
  done
done

echo "SUMMARY: pass=$PASS fail=$FAIL skip=$SKIP"
[ "$FAIL" -eq 0 ]
