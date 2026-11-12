#!/bin/bash
# run_tv3.sh: after run_tv2.sh, SLH-DSA R with raised node caps.
L=/root/batch-bench/leanvm
while ! grep -q '^tv2-done' /root/batch-bench/tv2-run.log 2>/dev/null; do sleep 30; done
cd $L && git checkout -q -- Cargo.lock; git fetch -q origin eip8288-batch-bench && git checkout -q -B eip8288-batch-bench FETCH_HEAD
source ~/.cargo/env
EIP8288_TABLE_VK=1 EIP8288_GENERIC_CODE_LOG=14 EIP8288_GENERIC_COMMITTED_LOG=23 EIP8288_MIXED_COMMITTED_LOG=29 EIP8288_MIXED_BUS_LOG=28 cargo build --release -p batch_leaf --features mixed >/dev/null 2>&1 && cp target/release/agg_bench bin/agg_tv14k23m29
log=$L/results/logs/agg-tv14k23m29-r_slhdsa128s_1_3
/usr/bin/time -v bin/agg_tv14k23m29 r slhdsa128s 1 3 > $log.out 2> $log.err
rss=$(grep "Maximum resident" $log.err | awk '{print $NF}')
grep '^{' $log.out | sed "s/}\$/,\"variant\":\"tv14k23m29\",\"peak_rss_kb\":${rss:-0},\"rc\":0}/" >> $L/results/agg.jsonl
echo "slh R done rss=$rss"
echo tv3-done
