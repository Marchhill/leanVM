#!/bin/bash
# build.sh <variant A|B|C> <profile>: builds agg_bench for one variant under one guest profile into
# bench-results/mac-ab/bin/agg_<variant>_<profile>. Profiles are the same build-time env for every variant.
set -eu
OUT=/Users/marc/nether/leanvm-batch-bench-ab/bench-results/mac-ab/bin
wt() { case $1 in A) echo /Users/marc/nether/leanvm-batch-bench-ab-a ;; B) echo /Users/marc/nether/leanvm-batch-bench-ab-b ;; C) echo /Users/marc/nether/leanvm-batch-bench-ab ;; esac; }
profile_env() {
  case $1 in
    c12m29) echo EIP8288_GENERIC_CODE_LOG=12 EIP8288_MIXED_COMMITTED_LOG=29 EIP8288_MIXED_BUS_LOG=28 ;;
    c12m27) echo EIP8288_GENERIC_CODE_LOG=12 ;;
    c13k25m30) echo EIP8288_GENERIC_CODE_LOG=13 EIP8288_GENERIC_COMMITTED_LOG=25 EIP8288_MIXED_COMMITTED_LOG=30 EIP8288_MIXED_BUS_LOG=30 ;;
    c13k25m29) echo EIP8288_GENERIC_CODE_LOG=13 EIP8288_GENERIC_COMMITTED_LOG=25 EIP8288_MIXED_COMMITTED_LOG=29 EIP8288_MIXED_BUS_LOG=28 ;;
    c14k23m30) echo EIP8288_GENERIC_CODE_LOG=14 EIP8288_GENERIC_COMMITTED_LOG=23 EIP8288_MIXED_COMMITTED_LOG=30 EIP8288_MIXED_BUS_LOG=30 ;;
    c14k23m29) echo EIP8288_GENERIC_CODE_LOG=14 EIP8288_GENERIC_COMMITTED_LOG=23 EIP8288_MIXED_COMMITTED_LOG=29 EIP8288_MIXED_BUS_LOG=28 ;;
    c14k27m30) echo EIP8288_GENERIC_CODE_LOG=14 EIP8288_GENERIC_COMMITTED_LOG=27 EIP8288_MIXED_COMMITTED_LOG=30 EIP8288_MIXED_BUS_LOG=30 ;;
    c14k27m29) echo EIP8288_GENERIC_CODE_LOG=14 EIP8288_GENERIC_COMMITTED_LOG=27 EIP8288_MIXED_COMMITTED_LOG=29 EIP8288_MIXED_BUS_LOG=28 ;;
    *) echo "unknown profile $1" >&2; exit 1 ;;
  esac
}
v=$1 p=$2
mkdir -p $OUT
cd "$(wt $v)"
env $(profile_env $p) cargo build --release -p batch_leaf --features mixed --bin agg_bench 2>&1 | tail -3
cp target/release/agg_bench $OUT/agg_${v}_$p
echo "built $v $p @ $(git rev-parse --short HEAD)+port: $(profile_env $p)"
