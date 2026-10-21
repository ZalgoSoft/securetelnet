#!/bin/bash
SIZES=(0 1 2 32768 32769 65535 65536 1048576)
COMPRESS=(none rle lz4)
NO_OVERWRITE=0
SHOW_CMDS=0
FILTER_SIZE=""
FILTER_COMPRESS=""

while [ $# -gt 0 ]; do
  case "$1" in
    --size) FILTER_SIZE="$2"; shift 2;;
    --compress) FILTER_COMPRESS="$2"; shift 2;;
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

if [ ! -f tests/server_priv ]; then
  ./securetelnet keygen tests/server_priv tests/server_pub
fi

PASS=0; FAIL=0; SKIP=0
PORT=23456

for sz in "${SIZES[@]}"; do
  if [ -n "$FILTER_SIZE" ] && [ "$sz" != "$FILTER_SIZE" ]; then continue; fi
  for cmp in "${COMPRESS[@]}"; do
    if [ -n "$FILTER_COMPRESS" ] && [ "$cmp" != "$FILTER_COMPRESS" ]; then continue; fi
    src="$OUT/src_$sz"
    head -c "$sz" /dev/urandom > "$src"
    upname="upload_${sz}_${cmp}_$$"
    downname="download_${sz}_${cmp}_$$"
    srv_extra=""
    [ "$NO_OVERWRITE" = 1 ] && srv_extra="--no-overwrite"
    srv_cmd="./securetelnet server $PORT tests/server_pub --mode file --compress $cmp --dh test --allow-test --session-dir $OUT $srv_extra"
    cli_cmd="./securetelnet client 127.0.0.1 $PORT tests/server_priv --mode file --compress $cmp --dh test --file-cmd \"put $src $upname\""
    [ "$SHOW_CMDS" = 1 ] && echo "SRV: $srv_cmd" && echo "CLI: $cli_cmd"
    eval "$srv_cmd" &
    SPID=$!
    sleep 0.2
    eval "$cli_cmd"
    wait $SPID 2>/dev/null

    if [ "$sz" -gt 65535 ]; then
      echo "EXPECTED FAIL: size=$sz compress=$cmp"
      FAIL=$((FAIL+1))
      continue
    fi

    if [ -f "$upname" ]; then
      h1=$(sha256sum "$src" | awk '{print $1}')
      h2=$(sha256sum "$upname" | awk '{print $1}')
      if [ "$h1" = "$h2" ]; then
        PASS=$((PASS+1)); echo "PASS: size=$sz compress=$cmp sha=$h1"
      else
        FAIL=$((FAIL+1)); echo "FAIL: size=$sz compress=$cmp sha mismatch"
      fi
    else
      FAIL=$((FAIL+1)); echo "FAIL: size=$sz compress=$cmp upload missing"
    fi
  done
done

echo "SUMMARY: pass=$PASS fail=$FAIL skip=$SKIP"
[ "$FAIL" -eq 0 ]
