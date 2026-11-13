#!/bin/bash
# run_ab.sh: A/B/C interleaved per rep (rep 0 is a discarded warm-up process); one process per
# measurement, no two processes concurrently. agg_bench r/merge also warm up in-process before the
# timed node.
cd "$(dirname "$0")/.." && source scripts/lib.sh
cell() { # name profile reps args...
  local name=$1 p=$2 reps=$3; shift 3
  for rep in $(seq 0 $reps); do for v in A B C; do measure $name $v $p $rep "$@"; done; done
}
echo "start $(date -u +%FT%TZ)"
cell r-null c12m29 5 r null 1 1
cell r-falcon512 c13k25m29 5 r falcon512 1 1
cell merge-null c12m29 5 merge null 1 1
cell r-slhdsa128s c14k23m30 3 r slhdsa128s 1 1
cell r-mldsa44 c14k27m30 3 r mldsa44 1 1
cell tree16-null c12m29 3 tree null 16 1
cell r-null-m27 c12m27 3 r null 1 1
echo "done $(date -u +%FT%TZ)"
