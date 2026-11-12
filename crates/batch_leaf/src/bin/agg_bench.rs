//! Aggregation workloads over batch leaves, against `rec_aggregation::eip8288_mixed`.
//!
//! `agg_bench check <scheme> <n>`: whether a leaf of n claims fits the generic profile.
//! `agg_bench r <scheme> <n> <repeat>`: one guest node verifying one leaf (R), then its verification.
//! `agg_bench merge <scheme> <n> <repeat>`: one guest node merging two such R-nodes.
//! `agg_bench tree <leaves> [scheme] [n]`: leaves aggregated pairwise to one root (guest nodes take <= 2 children).
//! Each line printed is JSON.

use std::time::Instant;

use batch_leaf::{Claim, Scheme, program, witness};
use lean_vm::cpu::{Program, Proof, prove};
use rec_aggregation::eip8288_mixed::{
    Dependency, GenericInput, MAX_CLAIMS_PER_BATCH_LEAF, MAX_GENERIC_BYTECODE_LOG, MAX_GENERIC_COMMITTED_LOG,
    MixedProof, aggregate_mixed, batch_statement, generic_recursion_supported, generic_verification_key,
};

struct Leaf {
    program: Program,
    proof: Proof,
    claims: Vec<Claim>,
    leaf_s: f64,
}

fn leaf<S: Scheme>(n: usize, items: &dyn Fn(usize) -> Vec<S::Item>, offset: usize) -> Leaf {
    let program = program::<S>();
    let all = items(n + offset);
    let (_, hints, pi, claims) = witness::<S>(all.into_iter().skip(offset).collect());
    assert_eq!(pi, batch_statement(&claims));
    let mut p = program.clone();
    for (name, entries) in hints.0 {
        p.set_witness(name, entries);
    }
    let t = Instant::now();
    let (proof, _) = prove(&p, pi, 1).expect("leaf proves");
    Leaf {
        program,
        proof,
        claims,
        leaf_s: t.elapsed().as_secs_f64(),
    }
}

fn deps(leaf: &Leaf) -> Vec<Dependency> {
    let key = generic_verification_key(&leaf.program).expect("encodable program");
    leaf.claims
        .iter()
        .map(|c| {
            let mut d = [0u8; 96];
            d[31] = 0x11;
            d[32..64].copy_from_slice(c);
            d[64..].copy_from_slice(&key);
            d
        })
        .collect()
}

fn node(children: &[MixedProof], leaves: &[&Leaf], selected: &[Dependency]) -> (MixedProof, f64) {
    let inputs: Vec<GenericInput> = leaves
        .iter()
        .map(|l| GenericInput {
            program: &l.program,
            proof: &l.proof,
            claims: &l.claims,
        })
        .collect();
    let t = Instant::now();
    let out = aggregate_mixed(children, &[], &inputs, selected, 1).expect("node proves");
    (out, t.elapsed().as_secs_f64())
}

fn report(kind: &str, scheme: &str, n: usize, run: usize, prove_s: f64, proof: &MixedProof, extra: &str) {
    let t = Instant::now();
    proof.verify().expect("node verifies");
    let verify_ms = t.elapsed().as_secs_f64() * 1e3;
    println!(
        "{{\"kind\":\"{kind}\",\"scheme\":\"{scheme}\",\"n\":{n},\"run\":{run},\"prove_s\":{prove_s:.4},\"verify_ms\":{verify_ms:.3},\"proof_bytes\":{},\"deps\":{},\"max_claims\":{MAX_CLAIMS_PER_BATCH_LEAF},\"code_log\":{MAX_GENERIC_BYTECODE_LOG},\"committed_log\":{MAX_GENERIC_COMMITTED_LOG},\"peak_rss_gib\":{:.2}{extra}}}",
        proof.to_bytes_without_deps().len(),
        proof.dependencies().len(),
        primitives::bench::peak_rss_bytes() as f64 / (1u64 << 30) as f64,
    );
}

fn sorted(mut d: Vec<Dependency>) -> Vec<Dependency> {
    d.sort();
    d
}

fn run<S: Scheme>(mode: &str, args: &[String], items: &dyn Fn(usize) -> Vec<S::Item>) {
    let n: usize = args.first().map_or(1, |a| a.parse().unwrap());
    let repeat: usize = args.get(1).map_or(1, |a| a.parse().unwrap());
    match mode {
        "check" => {
            let l = leaf::<S>(n, items, 0);
            println!(
                "{{\"kind\":\"check\",\"scheme\":\"{}\",\"n\":{n},\"bytecode\":{},\"supported\":{},\"leaf_s\":{:.3}}}",
                S::NAME,
                l.program.prog.len(),
                generic_recursion_supported(&l.program, &l.proof),
                l.leaf_s
            );
        }
        "r" => {
            let l = leaf::<S>(n, items, 0);
            let d = sorted(deps(&l));
            let _ = node(&[], &[&l], &d);
            for run in 0..repeat {
                let (p, s) = node(&[], &[&l], &d);
                report("r", S::NAME, n, run, s, &p, &format!(",\"leaf_s\":{:.3}", l.leaf_s));
            }
        }
        "merge" => {
            let (a, b) = (leaf::<S>(n, items, 0), leaf::<S>(n, items, n));
            let (pa, _) = node(&[], &[&a], &sorted(deps(&a)));
            let (pb, _) = node(&[], &[&b], &sorted(deps(&b)));
            let all = sorted([deps(&a), deps(&b)].concat());
            for run in 0..repeat {
                let (p, s) = node(&[pa.clone(), pb.clone()], &[], &all);
                report("merge", S::NAME, n, run, s, &p, "");
            }
        }
        "tree" => {
            let leaves_n = n;
            let per: usize = args.get(2).map_or(1, |a| a.parse().unwrap());
            let t0 = Instant::now();
            let leaves: Vec<Leaf> = (0..leaves_n).map(|i| leaf::<S>(per, items, i * per)).collect();
            let leaf_total: f64 = leaves.iter().map(|l| l.leaf_s).sum();
            let mut level: Vec<(MixedProof, Vec<Dependency>)> = Vec::new();
            let mut node_s = vec![0.0f64];
            for l in &leaves {
                let d = sorted(deps(l));
                let (p, s) = node(&[], &[l], &d);
                node_s[0] += s;
                level.push((p, d));
            }
            let mut depth = 1;
            while level.len() > 1 {
                node_s.push(0.0);
                let mut next = Vec::new();
                let mut it = level.into_iter();
                while let Some((a, da)) = it.next() {
                    match it.next() {
                        Some((b, db)) => {
                            let d = sorted([da, db].concat());
                            let (p, s) = node(&[a, b], &[], &d);
                            node_s[depth] += s;
                            next.push((p, d));
                        }
                        None => next.push((a, da)),
                    }
                }
                level = next;
                depth += 1;
            }
            let (root, _) = level.pop().unwrap();
            let levels: Vec<String> = node_s.iter().map(|s| format!("{s:.3}")).collect();
            report(
                "tree",
                S::NAME,
                leaves_n * per,
                0,
                node_s.iter().sum(),
                &root,
                &format!(
                    ",\"leaves\":{leaves_n},\"claims_per_leaf\":{per},\"guest_depth\":{depth},\"leaf_prove_total_s\":{leaf_total:.3},\"level_prove_s\":[{}],\"wall_s\":{:.3}",
                    levels.join(","),
                    t0.elapsed().as_secs_f64()
                ),
            );
        }
        other => panic!("unknown mode {other}"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args[1].as_str();
    let scheme = args[2].as_str();
    lean_vm::init_prover();
    let rest = &args[3..];
    match scheme {
        "null" => run::<batch_leaf::null_leaf::Null>(mode, rest, &batch_leaf::null_leaf::items),
        "xmss" => run::<batch_leaf::xmss_leaf::Xmss>(mode, rest, &batch_leaf::xmss_leaf::items),
        "falcon512" => run::<batch_leaf::falcon::Falcon512>(mode, rest, &batch_leaf::falcon::items),
        "mldsa44" => run::<batch_leaf::mldsa::MlDsa44>(mode, rest, &batch_leaf::mldsa::items),
        "slhdsa128s" => run::<batch_leaf::slhdsa::SlhDsaShake128s>(mode, rest, &batch_leaf::slhdsa::items),
        "mldsa44wa" => run::<batch_leaf::webauthn::MlDsa44WebAuthn>(mode, rest, &batch_leaf::webauthn::items),
        other => panic!("unknown scheme {other}"),
    }
}
