//! Standalone proofs of the mod-q arithmetic guest (tables, NTT round trip).

use std::collections::BTreeMap;

use lean_compiler::{compile, parse_with_replacements};
use lean_vm::cpu::Program;

use crate::Hints;
use crate::mq::{self, Mq};

use crate::mldsa::ARITH;

/// The zeta table and 256^-1, as the guest's constant arrays.
pub fn arith_placeholders(ps: &mut BTreeMap<String, String>) {
    ps.insert("ZT".into(), mq::records(&mq::zetas()));
    ps.insert("FINV_REC".into(), mq::records(&[mq::FINV]));
}

pub const ARITH_SETUP: &str = "
def setup_arith():
    tb = build_tables()
    zt = HeapBuf(POLY_CELLS)
    for k in unroll(0, POLY_CELLS):
        zt[GEN ** k] = ZT[k]
    finv = HeapBuf(REC)
    for k in unroll(0, REC):
        finv[GEN ** k] = FINV_REC[k]
    return tb, zt, finv
";

pub fn compile_with(source: &str, extra: impl FnOnce(&mut BTreeMap<String, String>)) -> Program {
    let mut ps = BTreeMap::new();
    arith_placeholders(&mut ps);
    extra(&mut ps);
    let source = format!("ZT = ZT_PLACEHOLDER\nFINV_REC = FINV_REC_PLACEHOLDER\n{source}");
    compile(
        &parse_with_replacements(
            &source,
            &ps.into_iter().map(|(k, v)| (format!("{k}_PLACEHOLDER"), v)).collect(),
        )
        .unwrap_or_else(|e| panic!("parse: {e}")),
    )
}

pub fn set_hints(program: &mut Program, hints: Hints) {
    for (name, entries) in hints.0 {
        program.set_witness(name, entries);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitives::field::F192;

    #[test]
    #[ignore]
    fn tables_cost() {
        let main = "\ndef main():\n    tb, zt, finv = setup_arith()\n    return\n";
        let program = compile_with(&format!("{ARITH}\n{ARITH_SETUP}\n{main}"), |_| {});
        let (_, stats) = lean_vm::cpu::prove(&program, [F192::ZERO; 2], 1).expect("proves");
        println!(
            "tables base {:?} sum {}",
            stats.base_counts,
            stats.base_counts.iter().sum::<usize>()
        );
    }

    #[test]
    #[ignore]
    fn ntt_roundtrip_proves() {
        let main = "
def main():
    tb, zt, finv = setup_arith()
    a = HeapBuf(POLY_CELLS)
    for k in mul_range(1, GEN ** 256):
        mq_load(a * k ** REC, tb)
    f = ntt(a, tb, zt)
    back = HeapBuf(POLY_CELLS)
    intt(f, tb, zt, finv, back)
    for k in mul_range(1, GEN ** 256):
        assert back[k ** REC * GEN ** 2] == a[k ** REC * GEN ** 2]
    return
";
        let mut program = compile_with(&format!("{ARITH}\n{ARITH_SETUP}\n{main}"), |_| {});
        let mut hints = Hints::default();
        let mut mq = Mq(&mut hints);
        let a: [u32; 256] = std::array::from_fn(|i| (i as u32 * 7919 + 13) % mq::Q);
        for &v in &a {
            mq.load(v);
        }
        let f = mq.ntt(&a);
        assert_eq!(mq.intt(&f), a);
        set_hints(&mut program, hints);
        let t = std::time::Instant::now();
        let (proof, stats) = lean_vm::cpu::prove(&program, [F192::ZERO; 2], 1).expect("proves");
        println!("prove {:?} {}", t.elapsed(), stats.details());
        println!("base {:?} bytecode {}", stats.base_counts, program.prog.len());
        lean_vm::cpu::verify(&program, &[F192::ZERO; 2], &proof).expect("verifies");
    }
}
