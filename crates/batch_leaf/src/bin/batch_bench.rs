//! `batch_bench <scheme> <n> [repeat]`: prove and verify one batch leaf of `n` claims
//! `repeat` times after one warm-up, printing one JSON line per measured run.
//! Run one `n` per process so `/usr/bin/time -v` reports that leaf's peak RSS.

use batch_leaf::{Measurement, Scheme, program, prove_leaf};

fn run<S: Scheme>(n: usize, repeat: usize, items: impl Fn(usize) -> Vec<S::Item>) {
    let started = std::time::Instant::now();
    let program = program::<S>();
    let compile_s = started.elapsed().as_secs_f64();
    let threads = std::env::var("LEANVM_NUM_THREADS").unwrap_or_else(|_| "all".into());
    let _ = prove_leaf::<S>(&program, items(n));
    for run in 0..repeat {
        let m: Measurement = prove_leaf::<S>(&program, items(n));
        let s = &m.stats;
        let base: usize = s.base_counts.iter().sum();
        println!(
            "{{\"scheme\":\"{}\",\"n\":{},\"run\":{},\"threads\":\"{}\",\"prove_s\":{:.4},\"verify_ms\":{:.3},\"proof_bytes\":{},\"base_cycles\":{},\"base_counts\":{:?},\"cycles\":{},\"committed\":{},\"log_mem\":{},\"mem_used\":{},\"bytecode\":{},\"compile_s\":{:.3}}}",
            S::NAME,
            m.n,
            run,
            threads,
            m.prove_s,
            m.verify_ms,
            m.proof_bytes,
            base,
            s.base_counts,
            s.cycles,
            s.committed,
            s.log_mem,
            s.mem_used,
            program.prog.len(),
            compile_s
        );
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let scheme = args.get(1).expect("scheme").as_str();
    let n: usize = args.get(2).expect("n").parse().expect("n");
    let repeat: usize = args.get(3).map_or(1, |r| r.parse().expect("repeat"));
    lean_vm::init_prover();
    match scheme {
        "xmss" => run::<batch_leaf::xmss_leaf::Xmss>(n, repeat, batch_leaf::xmss_leaf::items),
        "mldsa44" => run::<batch_leaf::mldsa::MlDsa44>(n, repeat, batch_leaf::mldsa::items),
        other => panic!("unknown scheme {other}"),
    }
}
