#!/bin/bash
# run_final.sh: after run_tv3.sh, all leaf sweeps and R at the final leaf code (no in-leaf order
# check, any-length ML-DSA message).
set -u
L=/root/batch-bench/leanvm
while ! grep -q '^tv3-done' /root/batch-bench/tv3-run.log 2>/dev/null; do sleep 30; done
cd $L && git checkout -q -- Cargo.lock; git fetch -q origin eip8288-batch-bench && git checkout -q -B eip8288-batch-bench FETCH_HEAD || exit 1
git log --oneline -1
source ~/.cargo/env
cargo build --release -p batch_leaf >/dev/null 2>&1
mkdir -p results/prev
for s in null falcon512 slhdsa128s mldsa44 mldsa44wa; do [ -f results/$s.jsonl ] && mv results/$s.jsonl results/prev/$s-$(date +%s).jsonl; done
cd /root/batch-bench
./run_leaf.sh null 3 1 4 16 64 256 1024
./run_leaf.sh falcon512 3 1 2 4 8
./run_leaf.sh slhdsa128s 3 1 4 16
./run_leaf.sh mldsa44 3 1 2
./run_leaf.sh mldsa44m32 3 1
./run_leaf.sh mldsa44m400 3 1
cd $L
build() { local name=$1; shift; env "$@" cargo build --release -p batch_leaf --features mixed >/dev/null 2>&1 && cp target/release/agg_bench bin/agg_$name; echo "built $name: $*"; }
run() {
  local v=$1; shift
  local log=$L/results/logs/agg-$v-final-$(echo "$@" | tr ' ' '_')
  /usr/bin/time -v $L/bin/agg_$v "$@" >"$log.out" 2>"$log.err"
  local rc=$? rss=$(grep "Maximum resident" "$log.err" | awk '{print $NF}')
  grep '^{' "$log.out" | sed "s/}\$/,\"variant\":\"$v-final\",\"peak_rss_kb\":${rss:-0},\"rc\":$rc}/" >> $L/results/agg.jsonl
  echo "$v $* rc=$rc rss_kb=$rss $(grep -o 'node proves: [A-Za-z]*' "$log.err" | head -1)"
}
build tv13k25 EIP8288_TABLE_VK=1 EIP8288_GENERIC_CODE_LOG=13 EIP8288_GENERIC_COMMITTED_LOG=25
run tv13k25 r falcon512 1 3
build tv14k23m29 EIP8288_TABLE_VK=1 EIP8288_GENERIC_CODE_LOG=14 EIP8288_GENERIC_COMMITTED_LOG=23 EIP8288_MIXED_COMMITTED_LOG=29 EIP8288_MIXED_BUS_LOG=28
run tv14k23m29 r slhdsa128s 1 2
build tv14k27m29 EIP8288_TABLE_VK=1 EIP8288_GENERIC_CODE_LOG=14 EIP8288_GENERIC_COMMITTED_LOG=27 EIP8288_MIXED_COMMITTED_LOG=29 EIP8288_MIXED_BUS_LOG=28
run tv14k27m29 r mldsa44 1 2
echo final-done
