# lib.sh: measure() runs one agg_bench process under /usr/bin/time -l after an idle check.
# Appends one JSON line per reported node to $R/agg.jsonl and an environment line to $R/env.log.
R=/Users/marc/nether/leanvm-batch-bench-ab/bench-results/mac-ab
BIN=$R/bin
mkdir -p $R/logs
idle_wait() { # wait (max 300 s) until the 1-minute load average is below 5
  local i=0
  while [ $i -lt 60 ]; do
    local l=$(sysctl -n vm.loadavg | awk '{print $2}')
    awk "BEGIN{exit !($l < 5)}" && return 0
    sleep 5; i=$((i+1))
  done
}
thermal() { # pmset thermal/performance warning state (Apple silicon reports warnings only, no speed limit)
  local t=$(pmset -g therm 2>/dev/null | grep -v '^Note: No .* has been recorded' | grep -v '^$' | tr '\n' ' ' | tr -s ' ')
  echo "${t:-none}" | tr ' ' '_'
}
measure() { # cell, variant, profile, rep, agg_bench args...
  local cell=$1 v=$2 p=$3 rep=$4; shift 4
  idle_wait
  local load=$(sysctl -n vm.loadavg | tr -d '{}' | xargs)
  local therm=$(thermal)
  local heavy=$(ps -Ao pcpu=,comm= | awk '$1>20' | tr '\n' ';')
  local log=$R/logs/$cell-$v-$p-rep$rep
  local t0=$(date +%s)
  /usr/bin/time -l $BIN/agg_${v}_$p "$@" >"$log.out" 2>"$log.err"
  local rc=$? t1=$(date +%s)
  local rss=$(grep "maximum resident set size" "$log.err" | awk '{print $1}')
  local faults=$(grep " page faults" "$log.err" | awk '{print $1}') swap=$(sysctl -n vm.swapusage | awk '{print $6}')
  local therm2=$(thermal)
  echo "$(date -u +%FT%TZ) cell=$cell variant=$v profile=$p rep=$rep rc=$rc wall_s=$((t1-t0)) rss_bytes=${rss:-0} major_faults=${faults:-na} swap_used_after=$swap load_before=\"$load\" thermal_before=$therm thermal_after=$therm2 heavy_before=\"$heavy\" args=\"$*\"" >> $R/env.log
  grep '^{' "$log.out" | sed "s/}\$/,\"cell\":\"$cell\",\"variant\":\"$v\",\"profile\":\"$p\",\"rep\":$rep,\"process_peak_rss_bytes\":${rss:-0},\"rc\":$rc}/" >> $R/agg.jsonl
  echo "$cell $v $p rep$rep rc=$rc wall=$((t1-t0))s rss=$(( ${rss:-0} / 1048576 ))MiB $(grep -o '"prove_s":[0-9.]*' "$log.out" | tail -1) $(grep -o 'panicked at [^ ]*' "$log.err" | head -1)"
}
