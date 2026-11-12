#!/bin/bash
cd /root/batch-bench
while ! grep -q '^extra-done' extra-run.log 2>/dev/null; do sleep 30; done
cd leanvm && git fetch -q origin eip8288-batch-bench && git checkout -q -B eip8288-batch-bench FETCH_HEAD && source ~/.cargo/env && cargo build --release -p batch_leaf >/dev/null 2>&1
cd .. && ./run_leaf.sh sha256 3 1 4 16
echo extra2-done
