//! EIP-8288 batch leaf programs: one generic leanVM CPU proof over a nonempty,
//! strictly increasing list of 32-byte claims, publishing
//! `get_batch_hash(claims) = Keccak-256(b"EIP8288:batch:v1" || claims)` as the two
//! 128-bit public-input cells of the generic-proof convention.
//!
//! A scheme supplies a zkDSL `verify_claim()` (returning the claim's two cells), its
//! placeholders, and per-claim hint streams. The batch size is a hint, so one compiled
//! program, i.e. one verification key, covers every batch size up to `MAX_CLAIMS`.

pub mod falcon;
pub mod mldsa;
pub mod mq;
#[cfg(test)]
mod mq_guest;
pub mod null_leaf;
pub mod sha256;
pub mod slhdsa;
pub mod xmss_leaf;

use std::collections::BTreeMap;
use std::time::Instant;

use lean_compiler::{compile, parse_with_replacements};
use lean_vm::cpu::{Program, Stats, prove, verify};
use primitives::field::{F192, G, g_pow};

pub const BATCH_TAG: &[u8; 16] = b"EIP8288:batch:v1";
/// Batch-size ceiling compiled into every leaf program (a range-check bound, at most 2^16).
pub const MAX_CLAIMS: usize = 4096;
/// Generic inputs and recursive children use log inverse rate 1 in the EIP-8288 profile.
pub const LOG_INV_RATE: usize = 1;

const BATCH_GUEST: &str = include_str!("../guests/batch.py");
const AGGREGATION_GUEST: &str = include_str!("../../rec_aggregation/guests/lean_ethereum.py");

pub type Claim = [u8; 32];

/// Named hint streams, in the order a program pops them.
#[derive(Default)]
pub struct Hints(pub BTreeMap<String, Vec<Vec<F192>>>);

impl Hints {
    pub fn push(&mut self, name: &str, entry: Vec<F192>) {
        self.0.entry(name.to_string()).or_default().push(entry);
    }
}

/// One scheme's leaf: its zkDSL claim verifier and the per-claim witnesses.
pub trait Scheme {
    type Item;
    const NAME: &'static str;
    /// zkDSL source defining `verify_claim()` and whatever it needs.
    fn source() -> String;
    fn placeholders(ps: &mut BTreeMap<String, String>);
    fn claim(item: &Self::Item) -> Claim;
    fn push_hints(item: &Self::Item, hints: &mut Hints);
    /// Hints the per-proof setup consumes (constant tables), pushed before any claim's.
    fn setup_hints(_: &mut Hints) {}
}

pub fn count(n: usize) -> F192 {
    F192::new(g_pow(n).0, 0, 0)
}

pub fn dsl_u128(value: F192) -> u128 {
    assert_eq!(value.c2, 0);
    (value.c0 as u128) | ((value.c1 as u128) << 64)
}

pub fn f192_literal(f: F192) -> String {
    format!("f192({},{},{})", f.c0, f.c1, f.c2)
}

pub fn flds(values: &[F192]) -> String {
    format!(
        "[{}]",
        values.iter().map(|&f| f192_literal(f)).collect::<Vec<_>>().join(", ")
    )
}

/// A 16-byte value as one canonical 128-bit cell (two little-endian lanes).
pub fn cell(bytes: &[u8]) -> F192 {
    let lane = |o: usize| u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
    F192::new(lane(0), lane(8), 0)
}

/// The generic-proof public input for 32 bytes of data.
pub fn public_input(data: &Claim) -> [F192; 2] {
    [cell(&data[..16]), cell(&data[16..])]
}

pub fn batch_hash(claims: &[Claim]) -> Claim {
    let mut bytes = BATCH_TAG.to_vec();
    for c in claims {
        bytes.extend_from_slice(c);
    }
    primitives::keccak::keccak256(&bytes)
}

/// The text of one top-level function (with its decorator) of the aggregation guest.
pub fn guest_function(name: &str) -> String {
    let lines: Vec<&str> = AGGREGATION_GUEST.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.starts_with(&format!("def {name}(")))
        .unwrap_or_else(|| panic!("guest has no {name}"));
    let def_line = start;
    let start = if start > 0 && lines[start - 1].starts_with('@') {
        start - 1
    } else {
        start
    };
    let end = (def_line + 1..lines.len())
        .find(|&i| !lines[i].is_empty() && !lines[i].starts_with(' '))
        .unwrap_or(lines.len());
    let mut out = lines[start..end].join("\n");
    out.push('\n');
    out
}

/// The aggregation guest's lines from the one starting with `from` up to the one starting with `to`.
pub fn guest_section(from: &str, to: &str) -> String {
    let start = AGGREGATION_GUEST.find(from).expect("section start");
    let end = start + AGGREGATION_GUEST[start..].find(to).expect("section end");
    AGGREGATION_GUEST[start..end].to_string()
}

fn common_placeholders(ps: &mut BTreeMap<String, String>) {
    let tag = cell(BATCH_TAG);
    ps.insert("TAG_0".into(), tag.c0.to_string());
    ps.insert("TAG_1".into(), tag.c1.to_string());
    ps.insert("MAX_CLAIMS".into(), MAX_CLAIMS.to_string());
    ps.insert("MAX_FULL_BLOCKS".into(), ((2 + 4 * MAX_CLAIMS) / 17 + 1).to_string());
    ps.insert("Y_INV".into(), f192_literal(F192::new(0, 1, 0).inv()));
    let coord: Vec<F192> = (0..192)
        .map(|i| match i / 64 {
            0 => F192::new(1u64 << i, 0, 0),
            1 => F192::new(0, 1u64 << (i - 64), 0),
            _ => F192::new(0, 0, 1u64 << (i - 128)),
        })
        .collect();
    ps.insert("COORD_BASIS".into(), flds(&coord));
    ps.insert("INV_GEN".into(), dsl_u128(F192::new(G.inv().0, 0, 0)).to_string());
}

/// The leaf program of scheme `S`.
pub fn program<S: Scheme>() -> Program {
    let source = format!("{}\n\n{}", S::source(), BATCH_GUEST);
    let mut ps = BTreeMap::new();
    common_placeholders(&mut ps);
    S::placeholders(&mut ps);
    let ps: BTreeMap<String, String> = ps.into_iter().map(|(k, v)| (format!("{k}_PLACEHOLDER"), v)).collect();
    // Global constants must precede every function: hoist them, the first definition winning.
    let mut seen = std::collections::BTreeSet::new();
    let (mut constants, mut body) = (String::new(), String::new());
    for l in source.lines() {
        let is_constant = l.split_once(" = ").is_some_and(|(name, _)| {
            !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        });
        if !is_constant {
            body.push_str(l);
            body.push('\n');
        } else if seen.insert(l.split_once(" = ").unwrap().0.to_string()) {
            constants.push_str(l);
            constants.push('\n');
        }
    }
    let source = format!("{constants}\n{body}");
    if std::env::var_os("BATCH_LEAF_DUMP").is_some() {
        std::fs::write(format!("/tmp/batch_leaf_{}.py", S::NAME), &source).ok();
    }
    let ast = parse_with_replacements(&source, &ps).unwrap_or_else(|e| panic!("parse: {e}"));
    if std::env::var_os("BATCH_LEAF_SIZE").is_some() {
        eprintln!(
            "{} code without filler: {}",
            S::NAME,
            lean_compiler::compile_without_filler(&ast).prog.len()
        );
    }
    compile(&ast)
}

/// Sort the items by claim, reject duplicates, and build the hint streams and public input.
pub fn witness<S: Scheme>(mut items: Vec<S::Item>) -> (Vec<S::Item>, Hints, [F192; 2], Vec<Claim>) {
    assert!(!items.is_empty() && items.len() <= MAX_CLAIMS);
    items.sort_by_cached_key(S::claim);
    let claims: Vec<Claim> = items.iter().map(S::claim).collect();
    assert!(claims.windows(2).all(|w| w[0] < w[1]), "claims must be distinct");
    let mut hints = Hints::default();
    let n = items.len();
    hints.push("n_claims", vec![count(n)]);
    let m = 2 + 4 * n;
    hints.push("sponge_split", vec![count(m / 17), count(m % 17)]);
    S::setup_hints(&mut hints);
    for item in &items {
        S::push_hints(item, &mut hints);
    }
    for w in claims.windows(2) {
        let lane = (0..4)
            .find(|&j| w[0][8 * j..8 * j + 8] != w[1][8 * j..8 * j + 8])
            .unwrap();
        hints.push("diff_lane", vec![count(lane)]);
    }
    let pi = public_input(&batch_hash(&claims));
    (items, hints, pi, claims)
}

pub struct Measurement {
    pub n: usize,
    pub prove_s: f64,
    pub verify_ms: f64,
    pub proof_bytes: u64,
    pub stats: Stats,
}

/// Prove and verify one leaf of `items`.
pub fn prove_leaf<S: Scheme>(program: &Program, items: Vec<S::Item>) -> Measurement {
    let n = items.len();
    let (_, hints, pi, _) = witness::<S>(items);
    let mut program = program.clone();
    for (name, entries) in hints.0 {
        program.set_witness(name, entries);
    }
    let started = Instant::now();
    let (proof, stats) = prove(&program, pi, LOG_INV_RATE).expect("leaf proves");
    let prove_s = started.elapsed().as_secs_f64();
    let started = Instant::now();
    verify(&program, &pi, &proof).expect("leaf verifies");
    let verify_ms = started.elapsed().as_secs_f64() * 1e3;
    let mut wrong = pi;
    wrong[0] += F192::ONE;
    assert!(
        verify(&program, &wrong, &proof).is_err(),
        "a wrong batch hash must not verify"
    );
    let proof_bytes = bincode::serialized_size(&proof).expect("serializable");
    Measurement {
        n,
        prove_s,
        verify_ms,
        proof_bytes,
        stats,
    }
}

/// A constant table as cells hinted in pairs and bound by a BLAKE2s chain (`load_checked`):
/// the pairs to hint and the chain's final digest cells.
pub fn checked_table(cells: &[F192]) -> (Vec<Vec<F192>>, [F192; 2]) {
    let mut cells = cells.to_vec();
    if cells.len() % 2 == 1 {
        cells.push(F192::ZERO);
    }
    let lanes = |a: F192, b: F192| [a.c0, a.c1, b.c0, b.c1].map(primitives::field::F64);
    let mut h = lanes(F192::ZERO, F192::ZERO);
    for pair in cells.chunks(2) {
        h = lean_vm::vmhash::compress(h, lanes(pair[0], pair[1]));
    }
    let pairs = cells.chunks(2).map(|p| p.to_vec()).collect();
    (pairs, [F192::new(h[0].0, h[1].0, 0), F192::new(h[2].0, h[3].0, 0)])
}

/// Placeholders for a checked table's pair count and digest.
pub fn checked_placeholders(ps: &mut BTreeMap<String, String>, name: &str, cells: &[F192]) {
    let (pairs, d) = checked_table(cells);
    ps.insert(format!("{name}_PAIRS"), pairs.len().to_string());
    ps.insert(format!("{name}_D0"), f192_literal(d[0]));
    ps.insert(format!("{name}_D1"), f192_literal(d[1]));
}

pub fn push_checked(hints: &mut Hints, cells: &[F192]) {
    for pair in checked_table(cells).0 {
        hints.push("table_cells", pair);
    }
}
