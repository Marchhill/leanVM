//! Proof-level properties of the VM: that its channels carry everything, and that a malformed input is an error rather than a panic.

use lean_compiler::{compile, parse};
use leanvm_core::cpu::{Proof, ProveError, prove, verify};
use leanvm_core::vmhash::compress;
use primitives::field::{F64, F192};

/// A program that hashes one block and publishes the digest, so its proof carries
/// the Keccak reduction over a real compression.
const HASHING: &str = "\
def main():
    a = StackBuf(2)
    a[0] = 5
    a[1] = 7
    c = StackBuf(2)
    keccak(a, a, c)
    p = 1
    p[1] = c[0]
    p[GEN] = c[1]
    return
";

/// The public input `HASHING` publishes.
fn hashing_pi() -> [F192; 2] {
    let h = [F64(5), F64(0), F64(7), F64(0)];
    let d = compress(h, h);
    [F192::new(d[0].0, d[1].0, 0), F192::new(d[2].0, d[3].0, 0)]
}

fn hashing_proof() -> (leanvm_core::cpu::Program, [F192; 2], Proof) {
    let program = compile(&parse(HASHING).expect("parse"));
    let pi = hashing_pi();
    let (proof, _) = prove(&program, pi, leanvm_core::pcs::TEST_LOG_INV_RATE).unwrap();
    verify(&program, &pi, &proof).expect("honest proof verifies");
    (program, pi, proof)
}

/// Out-of-process verification: everything travels in the two channels, so a proof
/// serializes, crosses a process boundary and verifies.
#[test]
fn a_proof_roundtrips_through_bytes() {
    let (program, pi, proof) = hashing_proof();
    let decoded = Proof::from_bytes(&proof.to_bytes()).expect("proof deserializes");
    assert_eq!(decoded, proof);
    verify(&program, &pi, &decoded).expect("a deserialized proof verifies");
}

/// An unsupported rate is an error, not a panic.
#[test]
fn an_unsupported_rate_is_an_error() {
    let program = compile(&parse(HASHING).expect("parse"));
    let rate = leanvm_core::pcs::MAX_LOG_INV_RATE + 1;
    assert_eq!(
        prove(&program, hashing_pi(), rate).err(),
        Some(ProveError::InvalidRate { log_inv_rate: rate })
    );
}

/// A public input that is not a 256-bit digest is an error, not a panic or a proof no verifier accepts.
#[test]
fn a_public_input_with_a_third_limb_is_an_error() {
    let program = compile(&parse(HASHING).expect("parse"));
    let mut pi = hashing_pi();
    pi[1].c2 = 1;
    assert_eq!(
        prove(&program, pi, leanvm_core::pcs::TEST_LOG_INV_RATE).err(),
        Some(ProveError::PublicInputNotDigest)
    );
}

/// A KECCAK table of any height proves and verifies: below the Keccak reduction's
/// block of 512 steps, where padding fills the floor, at it, and one step past it.
#[test]
fn any_number_of_steps_proves() {
    for n in [0usize, 1, 3, 512, 513] {
        let mut source = String::from("def main():\n    h0 = StackBuf(2)\n    h0[0] = 5\n    h0[1] = 7\n");
        for i in 0..n {
            source += &format!("    h{} = StackBuf(2)\n    keccak(h{i}, h{i}, h{})\n", i + 1, i + 1);
        }
        source += &format!("    p = 1\n    p[1] = h{n}[0]\n    p[GEN] = h{n}[1]\n    return\n");
        let mut h = [F64(5), F64(0), F64(7), F64(0)];
        for _ in 0..n {
            h = compress(h, h);
        }
        let pi = [F192::new(h[0].0, h[1].0, 0), F192::new(h[2].0, h[3].0, 0)];
        let program = compile(&parse(&source).expect("parse"));
        let (proof, stats) = prove(&program, pi, leanvm_core::pcs::TEST_LOG_INV_RATE).unwrap();
        assert_eq!(stats.rows[5], n, "{n} steps");
        verify(&program, &pi, &proof).unwrap_or_else(|e| panic!("{n} steps: {e:?}"));
    }
}

/// The memory announced is the least power of two covering the cells a run touches,
/// with no floor but the protocol's: the empty program proves on a memory of a few
/// cells, smaller than a line of the memory columns' fill.
#[test]
fn a_tiny_memory_proves() {
    let program = compile(&parse("def main():\n    return\n").expect("parse"));
    let pi = [F192::ZERO; 2];
    let (proof, stats) = prove(&program, pi, leanvm_core::pcs::TEST_LOG_INV_RATE).unwrap();
    assert!(stats.log_mem < 3, "memory of 2^{} cells", stats.log_mem);
    verify(&program, &pi, &proof).expect("honest proof verifies");
}

/// A committed program (`Program::committed`) proves and verifies by its table's commitment, and the value its
/// proof sends at the bus's point is the one a table-mode verifier evaluates there.
#[test]
fn a_committed_program_proves_and_verifies() {
    let (program, pi, table_proof) = hashing_proof();
    let table_summary = verify(&program, &pi, &table_proof).expect("table mode verifies");
    let committed = program.clone().committed();
    let commitment = committed.bytecode_commitment().expect("committed");
    assert_eq!(
        commitment.key,
        verifier::committed_key(commitment.log_instructions, &commitment.root)
    );
    assert_ne!(
        leanvm_core::cpu::fs_seed(&committed),
        leanvm_core::cpu::fs_seed(&program)
    );
    let (proof, _) = prove(&committed, pi, leanvm_core::pcs::TEST_LOG_INV_RATE).unwrap();
    let summary = verify(&committed, &pi, &proof).expect("committed mode verifies");
    let bytecode = verifier::Bytecode::committed(commitment.log_instructions, commitment.root).unwrap();
    let pi_bytes = leanvm_core::cpu::public_input_bytes(&pi);
    let replay = verifier::replay_unchecked(&bytecode, &pi_bytes, &leanvm_core::cpu::scalar_proof(&proof)).unwrap();
    assert_eq!(replay.bytecode_value, summary.bytecode_value);
    // Same program, same input: a different transcript, but the table there is one polynomial.
    let table = leanvm_core::cpu::layout::bytecode_table(program.prog());
    let words: Vec<u64> = table.iter().map(|w| w.0).collect();
    assert_eq!(
        verifier::Bytecode::new(&words)
            .evaluate(&summary.bytecode_point)
            .unwrap(),
        summary.bytecode_value
    );
    assert_ne!(table_summary.bytecode_point, summary.bytecode_point);
}

/// The committed mode's rejections: a proof verifies only under the key, root, size and value it was made with.
#[test]
fn a_committed_proof_binds_its_key_and_value() {
    let (program, pi, table_proof) = hashing_proof();
    let committed = program.clone().committed();
    let commitment = committed.bytecode_commitment().unwrap();
    let (proof, _) = prove(&committed, pi, leanvm_core::pcs::TEST_LOG_INV_RATE).unwrap();
    let pi_bytes = leanvm_core::cpu::public_input_bytes(&pi);
    let check = |bytecode: &verifier::Bytecode, proof: &Proof| {
        verifier::verify_execution(bytecode, &pi_bytes, &leanvm_core::cpu::scalar_proof(proof))
    };
    let honest = verifier::Bytecode::committed(commitment.log_instructions, commitment.root).unwrap();
    check(&honest, &proof).expect("honest");

    // Wrong root: another program's commitment, and a root one bit off.
    // Another program publishing the same digest: one more store into a scratch cell.
    let other_source = HASHING.replace("    p = 1\n", "    z = StackBuf(1)\n    z[0] = 3\n    p = 1\n");
    let other = compile(&parse(&other_source).expect("parse")).committed();
    let other_root = other.bytecode_commitment().unwrap().root;
    assert_ne!(other_root, commitment.root);
    assert!(
        check(
            &verifier::Bytecode::committed(commitment.log_instructions, other_root).unwrap(),
            &proof
        )
        .is_err()
    );
    let mut flipped = commitment.root;
    flipped[0] ^= 1;
    assert!(
        check(
            &verifier::Bytecode::committed(commitment.log_instructions, flipped).unwrap(),
            &proof
        )
        .is_err()
    );
    // Wrong table: the other program's proof under this key.
    let (other_proof, _) = prove(&other, pi, leanvm_core::pcs::TEST_LOG_INV_RATE).unwrap();
    verify(&other, &pi, &other_proof).expect("the other program's proof verifies under its own key");
    assert!(check(&honest, &other_proof).is_err());
    // Wrong size: the same root under another instruction count is another key and another layout.
    assert!(
        check(
            &verifier::Bytecode::committed(commitment.log_instructions + 1, commitment.root).unwrap(),
            &proof
        )
        .is_err()
    );
    // IV mismatch: a table-mode proof under the committed key, and the committed proof in table mode.
    assert!(check(&honest, &table_proof).is_err());
    assert!(verify(&program, &pi, &proof).is_err());
    // The value, and the opening: every stream scalar from the sent value on, changed, is rejected.
    let summary = check(&honest, &proof).unwrap();
    let at = proof
        .stream
        .iter()
        .position(|x| leanvm_core::cpu::to_scalar(x) == summary.bytecode_value)
        .expect("the value rides the stream");
    for offset in [at, proof.stream.len() - 1, proof.stream.len() - 40] {
        let mut tampered = proof.clone();
        tampered.stream[offset] += F192::ONE;
        assert!(
            check(&honest, &tampered).is_err(),
            "stream scalar {offset} of {}",
            proof.stream.len()
        );
    }
    // An opening of the table at another point: the bytecode opening's last Merkle phase swapped for the
    // main opening's first leaves would not even parse, so swap two of its paths instead.
    let mut tampered = proof.clone();
    let last = tampered.merkle.len() - 1;
    tampered.merkle[last].swap(0, 1);
    assert!(check(&honest, &tampered).is_err());
}
