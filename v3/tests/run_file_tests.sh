#!/usr/bin/env bash
set -u

# ============================================================
# Параметры (можно менять)
# ============================================================
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/securetelnet"
OUT="$ROOT/tests/out"
IN="$ROOT/tests/in"
LOGS="$ROOT/tests/logs"
KEYS="$ROOT/tests/keys"
PORT_BASE=62000
SHOW_CMDS=0
# Наборы опций (значения через пробел)
KDFS=(cube byte double)
CIPHERS=(ks16 raw block)
COMPRESS=(none rle lz4)
AUTHS=(schnorr hmac)
PRNGS=(xorshift mask clock)
MACS=(ks16 precalc)
SCHNORR=(plain cache)
DHS=(normal test)

# Размеры файлов (в байтах) по умолчанию
DEFAULT_SIZES=(0 1 2 32768 32769 65535 65536 1048576)

# Флаги, которые можно переопределить аргументами:
#   --size N       тестировать только файл размера N
#   --compress X   тестировать только режим компрессии X
SIZE_FILTER=""
COMPRESS_FILTER=""
OVERWRITE_FLAG="--overwrite"

# ============================================================
# Разбор аргументов
# ============================================================
while [ $# -gt 0 ]; do
    case "$1" in
        --show-cmds) SHOW_CMDS=1; shift ;;
        --size)      SIZE_FILTER="$2"; shift 2 ;;
        --compress)  COMPRESS_FILTER="$2"; shift 2 ;;
        --no-overwrite) OVERWRITE_FLAG=""; shift ;;
        -h|--help)
            echo "usage: $0 [--size N] [--compress X] [--no-overwrite] [--show-cmds]"
            exit 0 ;;
        *)
            echo "unknown arg: $1" >&2
            exit 1 ;;
    esac
done

if [ -n "$COMPRESS_FILTER" ]; then
    COMPRESS=("$COMPRESS_FILTER")
fi

# ============================================================
# Подготовка
# ============================================================
mkdir -p "$OUT" "$IN" "$LOGS" "$KEYS"

if [ ! -x "$BIN" ]; then
    echo "error: $BIN not found, run make first" >&2
    exit 1
fi

if ! command -v sha256sum >/dev/null 2>&1; then
    echo "error: sha256sum not found" >&2
    exit 1
fi

echo "=== generating keys ==="
"$BIN" keygen "$KEYS/client.priv" "$KEYS/client.pub" >/dev/null
cp "$KEYS/client.pub" "$KEYS/authorized_keys"

# ============================================================
# Генерация файлов
# ============================================================
echo "=== generating test files ==="
if [ -n "$SIZE_FILTER" ]; then
    SIZES=("$SIZE_FILTER")
else
    SIZES=("${DEFAULT_SIZES[@]}")
fi

declare -A FILE_OF_SIZE
for sz in "${SIZES[@]}"; do
    name="f${sz}"
    path="$OUT/${name}.bin"
    if [ ! -f "$path" ] || [ "$(stat -c%s "$path" 2>/dev/null || echo -1)" != "$sz" ]; then
        if [ "$sz" -eq 0 ]; then
            : > "$path"
        else
            head -c "$sz" /dev/urandom > "$path"
        fi
    fi
    FILE_OF_SIZE[$sz]="$name"
done

echo "=== files in $OUT ==="
for sz in "${SIZES[@]}"; do
    name="${FILE_OF_SIZE[$sz]}"
    src="$OUT/${name}.bin"
    h=$(sha256sum "$src" | awk '{print $1}')
    actual_sz=$(stat -c%s "$src")
    echo "  $name.bin size=$actual_sz sha256=$h"
done

# ============================================================
# Проверка доступности LZ4
# ============================================================
has_lz4() {
    pkg-config --exists liblz4 2>/dev/null && return 0
    if grep -q "HAVE_LZ4" "$ROOT/Makefile" 2>/dev/null; then return 0; fi
    return 1
}

# ============================================================
# Функция для поиска свободного имени
# ============================================================
free_name() {
    local p="$1"
    if [ ! -e "$p" ]; then echo "$p"; return 0; fi
    for i in $(seq 1 10000); do
        if [ ! -e "${p}.${i}" ]; then echo "${p}.${i}"; return 0; fi
    done
    return 1
}

# ============================================================
# Прогон одного кейса
# ============================================================
PASS=0
FAIL=0
SKIP=0
TOTAL=0
PORT=$PORT_BASE
RESULTS="$LOGS/results.txt"
: > "$RESULTS"

run_one() {
    local kdf="$1" cipher="$2" compress="$3" auth="$4" prng="$5" \
          mac="$6" schnorr="$7" dh="$8" name="$9" size="${10}"
    local src="$OUT/${name}.bin"

    # Каждый раз новое имя для записи в IN, чтобы не затирать
    local up_name down_name
    up_name=$(free_name "$IN/${name}.up.${kdf}_${cipher}_${compress}_${auth}_${prng}_${mac}_${schnorr}_${dh}.bin") || { echo "SKIP no free name"; SKIP=$((SKIP+1)); return; }
    down_name=$(free_name "$IN/${name}.down.${kdf}_${cipher}_${compress}_${auth}_${prng}_${mac}_${schnorr}_${dh}.bin") || { echo "SKIP no free name"; SKIP=$((SKIP+1)); return; }

    local slog="$LOGS/${name}_s_${kdf}_${cipher}_${compress}_${auth}_${prng}_${mac}_${schnorr}_${dh}.log"
    local clog="$LOGS/${name}_c_${kdf}_${cipher}_${compress}_${auth}_${prng}_${mac}_${schnorr}_${dh}.log"

    local common="--kdf $kdf --cipher $cipher --compress $compress --auth $auth --prng $prng --mac $mac --schnorr $schnorr --dh $dh"

    # ---- PUT: клиент читает src, сервер пишет up ----
    # ---- PUT: клиент читает src, сервер пишет up ----
    PORT=$((PORT + 1)); [ "$PORT" -gt 65000 ] && PORT=$PORT_BASE
    local srv_cmd="./securetelnet server $PORT tests/keys/authorized_keys --mode file $OVERWRITE_FLAG $common"
    local cli_cmd="./securetelnet client 127.0.0.1 $PORT tests/keys/client.priv --mode file --file-cmd 'put ${src#$ROOT/} ${up_name#$ROOT/}' $common"

    echo "-- put $name size=$size kdf=$kdf cipher=$cipher compress=$compress auth=$auth prng=$prng mac=$mac schnorr=$schnorr dh=$dh"

    if [ "$SHOW_CMDS" -eq 1 ]; then
        echo "   server: $srv_cmd"
        echo "   client: $cli_cmd"
    fi

    ( cd "$ROOT" && $BIN server "$PORT" "$KEYS/authorized_keys" --mode file $OVERWRITE_FLAG $common > "$slog" 2>&1 ) &
    local spid=$!
    sleep 0.3
    ( cd "$ROOT" && $BIN client 127.0.0.1 "$PORT" "$KEYS/client.priv" --mode file \
        --file-cmd "put ${src#$ROOT/} ${up_name#$ROOT/}" $common > "$clog" 2>&1 )
    local crc=$?
    wait "$spid" 2>/dev/null

    # ---- GET: сервер читает up, клиент пишет down ----
    PORT=$((PORT + 1)); [ "$PORT" -gt 65000 ] && PORT=$PORT_BASE
    srv_cmd="./securetelnet server $PORT tests/keys/authorized_keys --mode file $OVERWRITE_FLAG $common"
    cli_cmd="./securetelnet client 127.0.0.1 $PORT tests/keys/client.priv --mode file --file-cmd 'get ${up_name#$ROOT/} ${down_name#$ROOT/}' $common"

    echo "-- get $name size=$size kdf=$kdf cipher=$cipher compress=$compress auth=$auth prng=$prng mac=$mac schnorr=$schnorr dh=$dh"
    if [ "$SHOW_CMDS" -eq 1 ]; then
        echo "   server: $srv_cmd"
        echo "   client: $cli_cmd"
    fi

    ( cd "$ROOT" && $BIN server "$PORT" "$KEYS/authorized_keys" --mode file $OVERWRITE_FLAG $common > "$slog" 2>&1 ) &
    spid=$!
    sleep 0.3
    ( cd "$ROOT" && $BIN client 127.0.0.1 "$PORT" "$KEYS/client.priv" --mode file \
        --file-cmd "get ${up_name#$ROOT/} ${down_name#$ROOT/}" $common > "$clog" 2>&1 )
    crc=$?
    wait "$spid" 2>/dev/null

    if [ $crc -ne 0 ] || [ ! -f "$up_name" ]; then
        echo "   FAIL put $name $kdf/$cipher/$compress/$auth/$prng/$mac/$schnorr/$dh" | tee -a "$RESULTS"
        FAIL=$((FAIL + 1)); TOTAL=$((TOTAL + 1))
        return
    fi

    local up_size up_hash
    up_size=$(stat -c%s "$up_name")
    up_hash=$(sha256sum "$up_name" | awk '{print $1}')
    echo "   accepted: path=$up_name size=$up_size sha256=$up_hash"

    # ---- GET: сервер читает up, клиент пишет down ----
    PORT=$((PORT + 1)); [ "$PORT" -gt 65000 ] && PORT=$PORT_BASE
    srv_cmd="./securetelnet server $PORT tests/keys/authorized_keys --mode file $OVERWRITE_FLAG $common"
    cli_cmd="./securetelnet client 127.0.0.1 $PORT tests/keys/client.priv --mode file --file-cmd 'get ${up_name#$ROOT/} ${down_name#$ROOT/}' $common"

    echo "-- get $name size=$size kdf=$kdf cipher=$cipher compress=$compress auth=$auth prng=$prng mac=$mac schnorr=$schnorr dh=$dh"

    if [ "$SHOW_CMDS" -eq 1 ]; then
        echo "   server: $srv_cmd"
        echo "   client: $cli_cmd"
    fi

    ( cd "$ROOT" && $BIN server "$PORT" "$KEYS/authorized_keys" --mode file $OVERWRITE_FLAG $common > "$slog" 2>&1 ) &
    spid=$!
    sleep 0.3
    ( cd "$ROOT" && $BIN client 127.0.0.1 "$PORT" "$KEYS/client.priv" --mode file \
        --file-cmd "get ${up_name#$ROOT/} ${down_name#$ROOT/}" $common > "$clog" 2>&1 )
    crc=$?
    wait "$spid" 2>/dev/null

    if [ $crc -ne 0 ] || [ ! -f "$down_name" ]; then
        echo "   FAIL get $name $kdf/$cipher/$compress/$auth/$prng/$mac/$schnorr/$dh" | tee -a "$RESULTS"
        FAIL=$((FAIL + 1)); TOTAL=$((TOTAL + 1))
        return
    fi

    local down_size down_hash
    down_size=$(stat -c%s "$down_name")
    down_hash=$(sha256sum "$down_name" | awk '{print $1}')
    echo "   received: path=$down_name size=$down_size sha256=$down_hash"

    local src_hash
    src_hash=$(sha256sum "$src" | awk '{print $1}')

    if [ "$src_hash" = "$up_hash" ] && [ "$src_hash" = "$down_hash" ] && [ "$size" = "$down_size" ]; then
        echo "   PASS $name size=$size $kdf/$cipher/$compress/$auth/$prng/$mac/$schnorr/$dh" | tee -a "$RESULTS"
        PASS=$((PASS + 1))
    else
        echo "   FAIL hash $name size=$size $kdf/$cipher/$compress/$auth/$prng/$mac/$schnorr/$dh src=$src_hash up=$up_hash down=$down_hash down_size=$down_size" | tee -a "$RESULTS"
        FAIL=$((FAIL + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

# ============================================================
# Основной цикл
# ============================================================
echo "=== running matrix ==="
for sz in "${SIZES[@]}"; do
    name="${FILE_OF_SIZE[$sz]}"
    for kdf in "${KDFS[@]}"; do
        for cipher in "${CIPHERS[@]}"; do
            for compress in "${COMPRESS[@]}"; do
                if [ "$compress" = "lz4" ] && ! has_lz4; then
                    SKIP=$((SKIP + 1))
                    continue
                fi
                for auth in "${AUTHS[@]}"; do
                    for prng in "${PRNGS[@]}"; do
                        for mac in "${MACS[@]}"; do
                            for schnorr in "${SCHNORR[@]}"; do
                                for dh in "${DHS[@]}"; do
                                    run_one "$kdf" "$cipher" "$compress" "$auth" \
                                            "$prng" "$mac" "$schnorr" "$dh" \
                                            "$name" "$sz"
                                done
                            done
                        done
                    done
                done
            done
        done
    done
done

# ============================================================
# Итог
# ============================================================
echo "=== summary ==="
echo "total=$TOTAL pass=$PASS fail=$FAIL skip=$SKIP"
echo "results: $RESULTS"
echo "sent files: $OUT"
echo "received files (не удаляются): $IN"
echo "logs: $LOGS"

if [ $FAIL -ne 0 ]; then
    exit 1
fi
exit 0
