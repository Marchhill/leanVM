"""summarize.py: per cell and variant, medians over timed reps (rep >= 1) of agg.jsonl -> summary.csv."""
import json, statistics, sys, os
here = os.path.dirname(os.path.abspath(__file__))
root = os.path.dirname(here)
rows = [json.loads(l) for l in open(os.path.join(root, "agg.jsonl"))]


def time_l(r):
    """user, sys seconds and page reclaims of the process, from /usr/bin/time -l in its log."""
    f = os.path.join(root, "logs", f"{r['cell']}-{r['variant']}-{r['profile']}-rep{r['rep']}.err")
    user = sys_ = reclaims = 0.0
    for line in open(f):
        w = line.split()
        if len(w) >= 6 and w[1] == "real":
            user, sys_ = float(w[2]), float(w[4])
        elif line.strip().endswith("page reclaims"):
            reclaims = float(w[0])
    return user, sys_, reclaims
cells = {}
for r in rows:
    if r["rep"] >= 1:
        cells.setdefault((r["cell"], r["variant"], r["profile"]), []).append(r)
out = ["cell,variant,profile,reps,node_cycles,node_base_cycles,node_committed,guest_bytecode,prove_s_median,prove_s_min,prove_s_max,peak_rss_gib_median,proc_user_s_median,proc_sys_s_median,page_reclaims_m_median,proof_bytes,verify_ms_median,extra"]
for (cell, v, p), rs in sorted(cells.items(), key=lambda kv: (kv[0][0], kv[0][2], kv[0][1])):
    def uniq(k):
        vals = {r[k] for r in rs}
        return str(vals.pop()) if len(vals) == 1 else "|".join(map(str, sorted(vals)))
    t = [r["prove_s"] for r in rs]
    rss = statistics.median(r["process_peak_rss_bytes"] for r in rs) / 2**30
    tl = [time_l(r) for r in rs]
    usr, sy, rec = (statistics.median(x[i] for x in tl) for i in range(3))
    extra = ""
    if rs[0]["kind"] == "tree":
        extra = "wall_s_median=%.1f;leaf_prove_total_s_median=%.1f;level_prove_s_rep1=%s" % (
            statistics.median(r["wall_s"] for r in rs), statistics.median(r["leaf_prove_total_s"] for r in rs),
            "/".join(map(str, rs[0]["level_prove_s"])))
    out.append(f"{cell},{v},{p},{len(rs)},{uniq('node_cycles')},{uniq('node_base_cycles')},{uniq('node_committed')},{uniq('guest_bytecode')},"
               f"{statistics.median(t):.3f},{min(t):.3f},{max(t):.3f},{rss:.2f},{usr:.1f},{sy:.1f},{rec / 1e6:.2f},{uniq('proof_bytes')},{statistics.median(r['verify_ms'] for r in rs):.1f},{extra}")
open(os.path.join(root, "summary.csv"), "w").write("\n".join(out) + "\n")
print("\n".join(out))
