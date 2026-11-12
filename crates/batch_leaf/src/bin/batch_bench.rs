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

/// `k` chained Keccak-f permutations, each loaded from the heap as an absorb would.
fn keccak(k: usize, repeat: usize) {
    let src = format!(
        "def main():\n    st = HeapBuf(13 * {})\n    for c in unroll(0, 13):\n        st[GEN ** c] = 0\n    for i in mul_range(1, GEN ** {k}):\n        a = StackBuf(13)\n        cur = st * i ** 13\n        for c in unroll(0, 13):\n            a[c] = cur[GEN ** c]\n        keccak_permute(a, (st * (i * GEN) ** 13)[0:13])\n    return\n",
        k + 1
    );
    let program = lean_compiler::compile(&lean_compiler::parse(&src).expect("parse"));
    let pi = [primitives::field::F192::ZERO; 2];
    let _ = lean_vm::cpu::prove(&program, pi, 1).expect("proves");
    for run in 0..repeat {
        let t = std::time::Instant::now();
        let (proof, s) = lean_vm::cpu::prove(&program, pi, 1).expect("proves");
        let prove_s = t.elapsed().as_secs_f64();
        let t = std::time::Instant::now();
        lean_vm::cpu::verify(&program, &pi, &proof).expect("verifies");
        println!(
            "{{\"scheme\":\"keccakf\",\"n\":{k},\"run\":{run},\"prove_s\":{prove_s:.4},\"verify_ms\":{:.3},\"base_counts\":{:?},\"cycles\":{},\"committed\":{}}}",
            t.elapsed().as_secs_f64() * 1e3,
            s.base_counts,
            s.cycles,
            s.committed
        );
    }
}

/// `k` chained software SHA-256 compressions of one block.
fn sha256(k: usize, repeat: usize) {
    use batch_leaf::sha256::{IV, compress, gpow_list};
    let block: [u32; 16] = std::array::from_fn(|i| 0x0101_0101 * (i as u32 + 1));
    let mut hints = batch_leaf::Hints::default();
    let mut st = IV;
    for _ in 0..k {
        st = compress(&mut hints, st, block);
    }
    let src = format!(
        "SHA_KG = {}\nIVG = {}\nBLKG = {}\nOUTG = {}\n{}\ndef main():\n    kt = HeapBuf(64)\n    for t in unroll(0, 64):\n        kt[GEN ** t] = SHA_KG[t]\n    st = HeapBuf(264 * {})\n    for i in unroll(0, 8):\n        word_bits(IVG[i], st * GEN ** (33 * i))\n    blk = HeapBuf(528)\n    for i in unroll(0, 16):\n        word_bits(BLKG[i], blk * GEN ** (33 * i))\n    for c in mul_range(1, GEN ** {k}):\n        sha256_compress(st * c ** 264, blk, st * (c * GEN) ** 264, kt)\n    fin = st * GEN ** (264 * {k})\n    for i in unroll(0, 8):\n        assert fin[GEN ** (33 * i + 32)] == OUTG[i]\n    return\n",
        gpow_list(&batch_leaf::sha256::K_PUB),
        gpow_list(&IV),
        gpow_list(&block),
        gpow_list(&st),
        include_str!("../../guests/sha256.py"),
        k + 1
    );
    let mut program = lean_compiler::compile(&lean_compiler::parse(&src).expect("parse"));
    for (name, entries) in hints.0 {
        program.set_witness(name, entries);
    }
    let pi = [primitives::field::F192::ZERO; 2];
    let _ = lean_vm::cpu::prove(&program, pi, 1).expect("proves");
    for run in 0..repeat {
        let t = std::time::Instant::now();
        let (proof, s) = lean_vm::cpu::prove(&program, pi, 1).expect("proves");
        let prove_s = t.elapsed().as_secs_f64();
        lean_vm::cpu::verify(&program, &pi, &proof).expect("verifies");
        println!(
            "{{\"scheme\":\"sha256\",\"n\":{k},\"run\":{run},\"prove_s\":{prove_s:.4},\"verify_ms\":0,\"base_counts\":{:?},\"base_cycles\":{},\"cycles\":{},\"committed\":{}}}",
            s.base_counts,
            s.base_counts.iter().sum::<usize>(),
            s.cycles,
            s.committed
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
        "keccakf" => keccak(n, repeat),
        "sha256" => sha256(n, repeat),
        "xmss" => run::<batch_leaf::xmss_leaf::Xmss>(n, repeat, batch_leaf::xmss_leaf::items),
        "mldsa44" => run::<batch_leaf::mldsa::MlDsa44>(n, repeat, batch_leaf::mldsa::items),
        "falcon512" => run::<batch_leaf::falcon::Falcon512>(n, repeat, batch_leaf::falcon::items),
        "null" => run::<batch_leaf::null_leaf::Null>(n, repeat, batch_leaf::null_leaf::items),
        "slhdsa128s" => run::<batch_leaf::slhdsa::SlhDsaShake128s>(n, repeat, batch_leaf::slhdsa::items),
        "mldsa44wa" => run::<batch_leaf::webauthn::MlDsa44WebAuthn>(n, repeat, batch_leaf::webauthn::items),
        other => panic!("unknown scheme {other}"),
    }
}
