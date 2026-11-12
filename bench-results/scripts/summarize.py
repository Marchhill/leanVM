"""Medians per (scheme, n) for leaves and per workload for aggregation, from box/*.jsonl."""
import glob, json, statistics as st, sys, os
root = os.path.join(os.path.dirname(__file__), '..', 'box')
leaf, agg = {}, {}
for f in glob.glob(os.path.join(root, '*.jsonl')):
    for l in open(f):
        if not l.strip():
            continue
        r = json.loads(l)
        if 'kind' in r:
            agg.setdefault((r['variant'], r['kind'], r['scheme'], r['n']), []).append(r)
        else:
            # versioned files (e.g. falcon512-v1.jsonl) keep their own label
            label = os.path.basename(f)[:-len('.jsonl')]
            leaf.setdefault((label, r['n']), []).append(r)
out = open(os.path.join(root, '..', 'summary.csv'), 'w')
out.write('table,scheme,n,variant,kind,runs,prove_s_median,verify_ms_median,proof_bytes,base_cycles,padded_cycles,peak_rss_gib,extra\n')
for (s, n), rs in sorted(leaf.items()):
    out.write(f"leaf,{s},{n},,,{len(rs)},{st.median(r['prove_s'] for r in rs):.3f},{st.median(r['verify_ms'] for r in rs):.2f},{rs[0].get('proof_bytes','')},{rs[0].get('base_cycles', sum(rs[0].get('base_counts',[])))},{rs[0]['cycles']},{rs[0].get('peak_rss_kb',0)/2**20:.2f},\n")
for (v, k, s, n), rs in sorted(agg.items()):
    ok = [r for r in rs if r.get('rc', 0) == 0]
    extra = ';'.join(f"{key}={rs[0][key]}" for key in ('guest_depth', 'leaves', 'level_prove_s', 'leaf_s', 'deps') if key in rs[0])
    out.write(f"agg,{s},{n},{v},{k},{len(ok)},{st.median(r['prove_s'] for r in ok):.3f},{st.median(r['verify_ms'] for r in ok):.2f},{rs[0]['proof_bytes']},,,{rs[0].get('peak_rss_kb',0)/2**20:.2f},\"{extra}\"\n")
out.close()
print(open(os.path.join(root, '..', 'summary.csv')).read())
