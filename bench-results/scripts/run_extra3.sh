#!/bin/bash
cd /root/batch-bench
while ! grep -q '^extra2-done' extra2-run.log 2>/dev/null; do sleep 30; done
cd leanvm
/usr/bin/time -v bin/agg_c12m16 tree null 64 1 1 > results/logs/agg-c12m16-tree64.out 2> results/logs/agg-c12m16-tree64.err
grep '^{' results/logs/agg-c12m16-tree64.out | sed "s/}\$/,\"variant\":\"c12m16\",\"peak_rss_kb\":$(grep 'Maximum resident' results/logs/agg-c12m16-tree64.err | awk '{print $NF}'),\"rc\":0}/" >> results/agg.jsonl
echo extra3-done
