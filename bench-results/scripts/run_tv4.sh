#!/bin/bash
# run_tv4.sh: after run_tv3.sh, the WebAuthn leaf with origin binding (8280062d or later).
while ! grep -q '^tv3-done' /root/batch-bench/tv3-run.log 2>/dev/null; do sleep 30; done
cd /root/batch-bench/leanvm && git checkout -q -- Cargo.lock; git fetch -q origin eip8288-batch-bench && git checkout -q -B eip8288-batch-bench FETCH_HEAD
git log --oneline -1
source ~/.cargo/env
cargo build --release -p batch_leaf >/dev/null 2>&1
mv results/mldsa44wa.jsonl results/mldsa44wa-cb1b8c2e-no-origin.jsonl 2>/dev/null
cd /root/batch-bench && ./run_leaf.sh mldsa44wa 3 1 2
echo tv4-done
