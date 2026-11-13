EIP-8288 aggregation A/B/C on one Mac (branch eip8288-batch-bench-ab).

Host: Apple M2 Max (8P+4E cores, all 12 used: lean_vm default pool, LEANVM_NUM_THREADS unset), 32 GiB,
macOS 15 (Darwin 24.6), rustc 1.99.0, release (thin LTO, codegen-units 1), target-cpu=native.

Variants (each = the variant commit + one identical harness-port commit):
  A  ba421d50 (16 inner proofs per step; key = Keccak(domain || serialized code), no opcode/mode range check)
     branch eip8288-batch-bench-ab-a
  B  0025a71b (+ range-check opcode and DEREF mode before dispatch)          branch eip8288-batch-bench-ab-b
  C  f94dc8c5 (key = Keccak(domain || program commitment); serialized code not hashed)
     branch eip8288-batch-bench-ab (this branch)
Port: crates/batch_leaf and Cargo.lock from eip8288-batch-bench @c2581f63, plus in eip8288_mixed.rs only
the build-time profile overrides (env_or) and a LAST_NODE_STATS hook so agg_bench prints the node's
cycle counts. The EIP8288_TABLE_VK prototype is NOT ported: every variant runs its own key path.
Leaf guests (crates/batch_leaf, lean_vm, lean_compiler) are identical across A/B/C (the three commits
only touch crates/rec_aggregation), so leaf S/O figures from bench-results/ still apply; not re-run.

Profiles (same build env for all three variants in a cell; scripts/build.sh). Each is the smallest
mixed bound A fits (A fails with Capacity at mixed 29 for SLH-DSA and ML-DSA):
  c12m29     code 2^12, generic committed 2^22, mixed 29/28   R null, merge, 16-leaf tree
  c13k25m29  code 2^13, generic committed 2^25, mixed 29/28   R Falcon-512
  c14k23m30  code 2^14, generic committed 2^23, mixed 30/30   R SLH-DSA-SHAKE-128s
  c14k27m30  code 2^14, generic committed 2^27, mixed 30/30   R ML-DSA-44
  c12m27     code 2^12, default mixed 27/26                   R null (smaller profile; see summary)

Method (scripts/run_ab.sh, scripts/lib.sh): one agg_bench process per measurement, never two at once;
before each, wait (<=300 s) for the 1-minute load average < 5 (this Mac idles at ~4) and log load,
pmset thermal warnings, processes >20% CPU and swap use (env.log). Within each cell reps are
interleaved A,B,C,A,B,C,...; rep 0 is a discarded warm-up process, reps 1..N are timed. r and merge
also prove one untimed warm-up node in-process before the timed node. prove_s is the timed node's
prove time (aggregate_mixed only; leaf proving and verification excluded); tree prove_s is the sum
of all 31 node proofs. Peak RSS is /usr/bin/time -l maximum resident set size of the whole process
(leaf proof + warm-up node + timed node). Cycle counts come from lean_vm Stats of the timed node
(node_cycles = padded, node_base_cycles = unpadded) and are deterministic; summary.csv shows a
'|'-joined list if reps ever disagree. For tree, the cycle columns are the root node's.

Files: agg.jsonl (one line per reported node), env.log, driver.log, logs/ (stdout/stderr per process),
summary.csv (scripts/summarize.py: median/min/max over timed reps), scripts/.

Results (measured on this Mac; see summary.csv). Cycle counts are exact. Padded node cycles are
identical for A and B in every cell; B adds unpadded (base) cycles only (+18k null, +40k Falcon,
+72k SLH-DSA, +82k ML-DSA). C lowers padded node cycles by 7.2% and base cycles by 9.0-9.4% (vs B) in
every R cell (null 7,358,464 -> 6,832,136; Falcon 14,716,928 -> 13,664,264; SLH-DSA and ML-DSA,
both code 2^14, 29,433,856 -> 27,328,520), and leaves merge and tree root cycles unchanged.
A and B fail with Capacity at the default mixed bound (c12m27) for an empty leaf; C proves it.

Caveats:
- Memory pressure: this Mac had ~24 GiB resident in other applications and ~20-38 GiB swap in use.
  Cells with peak RSS >= ~18 GiB (Falcon, SLH-DSA, ML-DSA) ran with heavy compressor/swap activity
  (process sys time 40-215 s, 4-20 M page reclaims vs ~1 M for the light cells), so their wall
  times include paging cost and overstate compute; the A/B/C ordering held in every rep but the
  ratio is not a compute ratio. R null, merge and tree (<= 13 GiB) ran with ~5 s sys time.
- Spotlight (mds_stores) used ~1 core during much of the R null/Falcon/merge cells (logged per
  run in env.log); interleaving spreads it across variants.
- pmset recorded no thermal or performance warning at any point (thermal_before/after=none).
- Peak RSS is per process (leaf proof + warm-up node + timed node), not the timed node alone.
