#!/bin/bash
# run_leaf.sh <scheme> <repeat> <n...>: one process per N, peak RSS from /usr/bin/time -v.
# Appends JSON lines to results/<scheme>.jsonl and logs to results/logs/.
set -u
scheme=$1; repeat=$2; shift 2
cd /root/batch-bench/leanvm
mkdir -p results/logs
for n in "$@"; do
  log=results/logs/${scheme}-n${n}.log
  /usr/bin/time -v ./target/release/batch_bench "$scheme" "$n" "$repeat" >"$log.out" 2>"$log.err"
  rc=$?
  rss=$(grep "Maximum resident set size" "$log.err" | awk '{print $NF}')
  grep '^{' "$log.out" | sed "s/}\$/,\"peak_rss_kb\":${rss:-0},\"rc\":$rc}/" >> results/${scheme}.jsonl
  echo "$scheme n=$n rc=$rc rss_kb=$rss"
  [ $rc -ne 0 ] && tail -5 "$log.err"
done
