#!/bin/bash
# run_tv2.sh: new leaves (SLH-DSA, WebAuthn, re-run ML-DSA) and the table-seed key variants.
set -u
L=/root/batch-bench/leanvm
cd $L && git checkout -q -- Cargo.lock; git fetch -q origin eip8288-batch-bench && git checkout -q -B eip8288-batch-bench FETCH_HEAD || exit 1
git log --oneline -1
source ~/.cargo/env
mkdir -p results/logs bin
cargo build --release -p batch_leaf >/dev/null 2>&1
mv results/mldsa44.jsonl results/mldsa44-d6820656.jsonl 2>/dev/null
cd /root/batch-bench
./run_leaf.sh slhdsa128s 3 1 4 16 64 256
./run_leaf.sh mldsa44 3 1 2
./run_leaf.sh mldsa44wa 3 1 2
cd $L
build() { local name=$1; shift; env "$@" cargo build --release -p batch_leaf --features mixed >/dev/null 2>&1 && cp target/release/agg_bench bin/agg_$name; echo "built $name: $*"; }
run() {
  local v=$1; shift
  local log=$L/results/logs/agg-$v-$(echo "$@" | tr ' ' '_')
  /usr/bin/time -v $L/bin/agg_$v "$@" >"$log.out" 2>"$log.err"
  local rc=$? rss=$(grep "Maximum resident" "$log.err" | awk '{print $NF}')
  grep '^{' "$log.out" | sed "s/}\$/,\"variant\":\"$v\",\"peak_rss_kb\":${rss:-0},\"rc\":$rc}/" >> $L/results/agg.jsonl
  echo "$v $* rc=$rc rss_kb=$rss $(grep -o 'node proves: [A-Za-z]*' "$log.err" | head -1)"
}
build tv12 EIP8288_TABLE_VK=1 EIP8288_GENERIC_CODE_LOG=12
run tv12 r null 1 3
run tv12 r null 16 3
run tv12 merge null 1 2
run tv12 tree null 16 1 1
build tv13k25 EIP8288_TABLE_VK=1 EIP8288_GENERIC_CODE_LOG=13 EIP8288_GENERIC_COMMITTED_LOG=25
run tv13k25 r falcon512 1 3
run tv13k25 merge falcon512 1 2
run tv13k25 tree falcon512 16 1 1
build tv14k23 EIP8288_TABLE_VK=1 EIP8288_GENERIC_CODE_LOG=14 EIP8288_GENERIC_COMMITTED_LOG=23
run tv14k23 r slhdsa128s 1 3
build tv14k27m29 EIP8288_TABLE_VK=1 EIP8288_GENERIC_CODE_LOG=14 EIP8288_GENERIC_COMMITTED_LOG=27 EIP8288_MIXED_COMMITTED_LOG=29 EIP8288_MIXED_BUS_LOG=28
run tv14k27m29 r mldsa44 1 2
run tv12 tree null 64 1 1
echo tv2-done
