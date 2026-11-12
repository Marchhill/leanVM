#!/bin/bash
# run_extra.sh: after run_agg.sh, the Keccak-f microbenchmark and the guest's own
# SPHINCS (NiceTry, Keccak-256) aggregation as the FIPS 205-shaped proxy.
cd /root/batch-bench
while ! grep -q '^done' agg-run.log 2>/dev/null; do sleep 30; done
cd leanvm && git fetch -q origin eip8288-batch-bench && git checkout -q -B eip8288-batch-bench FETCH_HEAD
source ~/.cargo/env
cargo build --release -p batch_leaf >/dev/null 2>&1
cd .. && ./run_leaf.sh keccakf 3 1024 4096 16384 65536
cd leanvm && cargo build --release --bin leanvm >/dev/null 2>&1
for n in 1 4 16; do
  /usr/bin/time -v ./target/release/leanvm aggregate --sphincs $n --log-inv-rate 1 --repeat 3 > results/logs/sphincs-guest-n$n.out 2> results/logs/sphincs-guest-n$n.err
  echo "sphincs-guest n=$n rc=$? $(grep 'Maximum resident' results/logs/sphincs-guest-n$n.err)"
done
echo extra-done
