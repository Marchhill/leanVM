#!/bin/bash
# run_agg.sh: build guest-profile variants and run the aggregation workloads, one process
# each under /usr/bin/time -v. JSON lines go to results/agg.jsonl, logs to results/logs/.
set -u
cd /root/batch-bench/leanvm
source ~/.cargo/env
mkdir -p results/logs bin
build() { # name, env assignments...
  local name=$1; shift
  env "$@" cargo build --release -p batch_leaf --features mixed >/dev/null 2>&1 && cp target/release/agg_bench bin/agg_$name
  echo "built $name: $*"
}
run() { # variant, args...
  local v=$1; shift
  local log=results/logs/agg-$v-$(echo "$@" | tr ' ' '_')
  /usr/bin/time -v bin/agg_$v "$@" >"$log.out" 2>"$log.err"
  local rc=$? rss=$(grep "Maximum resident" "$log.err" | awk '{print $NF}')
  grep '^{' "$log.out" | sed "s/}\$/,\"variant\":\"$v\",\"peak_rss_kb\":${rss:-0},\"rc\":$rc}/" >> results/agg.jsonl
  echo "$v $* rc=$rc rss_kb=$rss $(grep -o 'node proves: [A-Za-z]*' "$log.err" | head -1)"
}
build c12m16 EIP8288_GENERIC_CODE_LOG=12 EIP8288_MIXED_COMMITTED_LOG=29 EIP8288_MIXED_BUS_LOG=28
run c12m16 r null 1 3
run c12m16 r null 16 3
run c12m16 merge null 1 2
run c12m16 merge null 16 1
run c12m16 tree null 16 1 1
build c12m64 EIP8288_GENERIC_CODE_LOG=12 EIP8288_MIXED_COMMITTED_LOG=29 EIP8288_MIXED_BUS_LOG=28 EIP8288_MAX_CLAIMS=64
run c12m64 r null 1 1
run c12m64 r null 64 1
build c12m256 EIP8288_GENERIC_CODE_LOG=12 EIP8288_MIXED_COMMITTED_LOG=29 EIP8288_MIXED_BUS_LOG=28 EIP8288_MAX_CLAIMS=256
run c12m256 r null 1 1
run c12m256 r null 256 1
build c13m16 EIP8288_GENERIC_CODE_LOG=13 EIP8288_MIXED_COMMITTED_LOG=29 EIP8288_MIXED_BUS_LOG=28
run c13m16 r null 1 1
run c13m16 r xmss 1 2
run c13m16 r falcon512 1 2
run c13m16 r xmss 16 1
build c15m16 EIP8288_GENERIC_CODE_LOG=15 EIP8288_GENERIC_COMMITTED_LOG=27 EIP8288_MIXED_COMMITTED_LOG=30 EIP8288_MIXED_BUS_LOG=30
run c15m16 r mldsa44 1 1
echo done
