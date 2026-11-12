EIP-8288 batch-leaf benchmarks (branch eip8288-batch-bench, on eip8288-batch-leaves @654e12a7).
box/   : root@178.79.137.95, AMD EPYC 7642 (KVM, 6 vCPU, all 6 threads used), 15 GiB RAM + 8 GiB swap,
         rustc 1.100.0, release, target-cpu=native. environment.txt has lscpu/free.
         *.jsonl one line per measured run (after one warm-up), peak_rss_kb from /usr/bin/time -v
         (one N per process); logs/ has stdout/stderr per run and the driver logs.
         Leaf sweeps were measured at: xmss 8a187320, mldsa44 ab09dbcc, falcon512 f4669af7 (pre-rebase
         commits, same leaf code), null/keccakf/sha256 at c32e2934/c22d96f6.
mac/   : Apple M-series 12 cores, 32 GiB (only the Falcon R run, which does not fit the box).
summary.csv: medians per point (scripts/summarize.py).
Aggregation variants (build-time env, see rec_aggregation/src/eip8288_mixed.rs env_or):
  c12m16  GENERIC_CODE_LOG=12, MIXED_COMMITTED_LOG=29, MIXED_BUS_LOG=28, MAX_CLAIMS=16
  c12m64 / c12m256  same with MAX_CLAIMS=64 / 256
  c13m16  GENERIC_CODE_LOG=13, mixed 29/28
  c15m16  GENERIC_CODE_LOG=15, GENERIC_COMMITTED_LOG=27, mixed 30/30
  c14k26m30 (mac) GENERIC_CODE_LOG=14, GENERIC_COMMITTED_LOG=26, mixed 30/30

Follow-up round (table-seed key, leaf optimisations, SLH-DSA, any-length ML-DSA):
  *-v1.jsonl, mldsa44-d6820656.jsonl, prev/: earlier leaf code (before optimisation / before the
  in-leaf order check was dropped); falcon512.jsonl, slhdsa128s.jsonl, mldsa44*.jsonl, null.jsonl:
  final leaf code at 7885e986 (order check dropped; ML-DSA over any-length messages, mldsa44 =
  69-byte passkey message, mldsa44m32 / m400 = 32 / 400 bytes).
  Aggregation variants tv*: EIP8288_TABLE_VK=1 (key = the program's Fiat-Shamir seed over its
  bytecode table); tv12 code 2^12; tv13k25 code 2^13 committed 2^25 (default node caps);
  tv14k23m29 / tv14k27m29 code 2^14 with node caps 29/28. "-final" rows use the final leaves.
