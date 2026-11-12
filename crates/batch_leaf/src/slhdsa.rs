//! SLH-DSA-SHAKE-128s (FIPS 205) leaf: `guests/slhdsa.py`.

use std::collections::BTreeMap;

use fips205::slh_dsa_shake_128s;
use fips205::traits::{KeyGen, SerDes, Signer, Verifier};
use primitives::field::F192;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::mldsa::{LANES, bt_cells, push_bytes};
use crate::{Claim, Hints, Scheme, cell, count, dsl_u128};

const GUEST: &str = include_str!("../guests/slhdsa.py");
pub const CLAIM_TAG: &[u8; 16] = b"EIP8288:slh128s1";
const N: usize = 16;
const K: usize = 14;
const A: usize = 12;
const D: usize = 7;
const HP: usize = 9;
const LEN: usize = 35;

pub struct SlhDsaShake128s;

pub struct SlhItem {
    pub pk: [u8; 32],
    pub msg: [u8; 32],
    pub sig: Vec<u8>,
}

pub fn items(n: usize) -> Vec<SlhItem> {
    (0..n)
        .map(|i| {
            let seed = |tag: u8| {
                let mut s = [tag; N];
                s[..8].copy_from_slice(&(i as u64).to_le_bytes());
                s
            };
            let (pk, sk) = slh_dsa_shake_128s::KG::keygen_with_seeds(&seed(1), &seed(2), &seed(3));
            let mut msg = [0x33u8; 32];
            msg[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let sig = sk.try_sign(&msg, &[], false).expect("signs");
            assert!(pk.verify(&msg, &sig, &[]));
            SlhItem {
                pk: pk.into_bytes(),
                msg,
                sig: sig.to_vec(),
            }
        })
        .collect()
}

fn shake(parts: &[&[u8]], out: &mut [u8]) {
    let mut h = sha3::Shake256::default();
    for p in parts {
        h.update(p);
    }
    h.finalize_xof().read(out);
}

fn adrs(layer: u32, tree: u64, typ: u32, w1: u32, w2: u32, w3: u32) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[0..4].copy_from_slice(&layer.to_be_bytes());
    a[8..16].copy_from_slice(&tree.to_be_bytes());
    a[16..20].copy_from_slice(&typ.to_be_bytes());
    a[20..24].copy_from_slice(&w1.to_be_bytes());
    a[24..28].copy_from_slice(&w2.to_be_bytes());
    a[28..32].copy_from_slice(&w3.to_be_bytes());
    a
}

fn th(seed: &[u8], ad: &[u8; 32], msg: &[&[u8]]) -> [u8; N] {
    let mut parts: Vec<&[u8]> = vec![seed, ad];
    parts.extend_from_slice(msg);
    let mut out = [0u8; N];
    shake(&parts, &mut out);
    out
}

fn cells(bytes: &[u8]) -> Vec<F192> {
    bytes.chunks(16).map(cell).collect()
}

impl Scheme for SlhDsaShake128s {
    type Item = SlhItem;
    const NAME: &'static str = "slhdsa128s";

    fn source() -> String {
        format!("{LANES}\n{GUEST}\n\n{}", crate::guest_function("order_children"))
    }

    fn placeholders(ps: &mut BTreeMap<String, String>) {
        ps.insert("CLAIM_TAG".into(), dsl_u128(cell(CLAIM_TAG)).to_string());
        crate::checked_placeholders(ps, "BT", &bt_cells());
    }

    fn setup_hints(hints: &mut Hints) {
        crate::push_checked(hints, &bt_cells());
    }

    fn claim(item: &SlhItem) -> Claim {
        let mut b = CLAIM_TAG.to_vec();
        b.extend_from_slice(&item.pk);
        b.extend_from_slice(&item.msg);
        primitives::keccak::keccak256(&b)
    }

    fn push_hints(item: &SlhItem, hints: &mut Hints) {
        let (seed, root) = (&item.pk[..N], &item.pk[N..]);
        let sig = &item.sig;
        let r = &sig[..N];
        hints.push("sl_r", vec![cell(r)]);
        hints.push("sl_pk", vec![cell(seed), cell(root)]);
        hints.push("sl_msg", cells(&item.msg));
        push_bytes(hints, &item.msg);
        let mut digest = [0u8; 30];
        shake(&[r, seed, root, &[0, 0], &item.msg], &mut digest);
        let be = |b: &[u8]| b.iter().fold(0u64, |acc, &x| acc << 8 | x as u64);
        let idx_tree = be(&digest[21..28]) & ((1 << 54) - 1);
        let idx_leaf = (be(&digest[28..30]) & ((1 << HP) - 1)) as u32;
        let md_bit = |s: usize| (digest[s / 8] >> (7 - s % 8)) & 1;

        // FORS.
        let fors = &sig[N..N + K * (A + 1) * N];
        let mut roots = Vec::new();
        for i in 0..K {
            let idx = (0..A).fold(0u32, |acc, b| acc << 1 | md_bit(A * i + b) as u32);
            let t = &fors[i * (A + 1) * N..(i + 1) * (A + 1) * N];
            hints.push("sl_fors", cells(t));
            let base = (i as u32) << A;
            let mut node = th(seed, &adrs(0, idx_tree, 3, idx_leaf, 0, base + idx), &[&t[..N]]);
            for z in 1..=A {
                let sib = &t[z * N..(z + 1) * N];
                let ad = adrs(0, idx_tree, 3, idx_leaf, z as u32, (base + idx) >> z);
                node = if (idx >> (z - 1)) & 1 == 0 {
                    th(seed, &ad, &[&node, sib])
                } else {
                    th(seed, &ad, &[sib, &node])
                };
            }
            roots.extend_from_slice(&node);
        }
        let mut signed = th(seed, &adrs(0, idx_tree, 4, idx_leaf, 0, 0), &[&roots]);

        // Hypertree.
        let ht = &sig[N + K * (A + 1) * N..];
        let (mut tree, mut leaf) = (idx_tree, idx_leaf);
        for j in 0..D {
            let layer = &ht[j * (LEN + HP) * N..(j + 1) * (LEN + HP) * N];
            let mut digits: Vec<u32> = signed
                .iter()
                .flat_map(|&b| [(b >> 4) as u32, (b & 15) as u32])
                .collect();
            let csum: u32 = digits.iter().map(|d| 15 - d).sum();
            digits.extend([(csum >> 8) & 15, (csum >> 4) & 15, csum & 15]);
            hints.push("sl_digits", digits.iter().map(|&d| count(d as usize)).collect());
            hints.push("sl_wots", cells(&layer[..LEN * N]));
            let mut tips = Vec::new();
            for (c, &d) in digits.iter().enumerate() {
                let mut v: [u8; N] = layer[c * N..(c + 1) * N].try_into().unwrap();
                for s in d..15 {
                    v = th(seed, &adrs(j as u32, tree, 0, leaf, c as u32, s), &[&v]);
                }
                tips.extend_from_slice(&v);
            }
            let mut node = th(seed, &adrs(j as u32, tree, 1, leaf, 0, 0), &[&tips]);
            let auth = &layer[LEN * N..];
            hints.push("sl_auth", cells(auth));
            for z in 1..=HP {
                let sib = &auth[(z - 1) * N..z * N];
                let ad = adrs(j as u32, tree, 2, 0, z as u32, leaf >> z);
                node = if (leaf >> (z - 1)) & 1 == 0 {
                    th(seed, &ad, &[&node, sib])
                } else {
                    th(seed, &ad, &[sib, &node])
                };
            }
            signed = node;
            leaf = (tree & ((1 << HP) - 1)) as u32;
            tree >>= HP;
        }
        assert_eq!(&signed, root, "host SLH-DSA recomputation rejects the signature");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_recomputes_signatures() {
        for item in items(2) {
            SlhDsaShake128s::push_hints(&item, &mut Hints::default());
            let mut bad = Hints::default();
            let mut forged = SlhItem {
                pk: item.pk,
                msg: item.msg,
                sig: item.sig.clone(),
            };
            forged.msg[0] ^= 1;
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| SlhDsaShake128s::push_hints(
                    &forged, &mut bad
                )))
                .is_err()
            );
        }
    }
}

#[cfg(test)]
mod soundness {
    use super::*;
    use crate::{program, witness};

    fn proves(program: &lean_vm::cpu::Program, hints: &Hints, pi: [F192; 2]) -> bool {
        let mut program = program.clone();
        for (name, entries) in &hints.0 {
            program.set_witness(name.clone(), entries.clone());
        }
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            lean_vm::cpu::prove(&program, pi, 1)
                .ok()
                .is_some_and(|(proof, _)| lean_vm::cpu::verify(&program, &pi, &proof).is_ok())
        }))
        .unwrap_or(false)
    }

    #[test]
    #[ignore]
    fn mutated_witnesses_do_not_prove() {
        let program = program::<SlhDsaShake128s>();
        let (_, hints, pi, _) = witness::<SlhDsaShake128s>(items(1));
        assert!(proves(&program, &hints, pi));
        let flip = |name: &str, entry: usize, slot: usize, f: &dyn Fn(F192) -> F192| {
            let mut h = Hints(hints.0.clone());
            let e = &mut h.0.get_mut(name).unwrap()[entry][slot];
            *e = f(*e);
            h
        };
        let next = |x: F192| x * F192::new(primitives::field::G.0, 0, 0);
        let one = |x: F192| x + F192::ONE;
        let cases: Vec<(&str, Hints)> = vec![
            ("message cell", flip("sl_msg", 0, 1, &one)),
            ("pk seed", flip("sl_pk", 0, 0, &one)),
            ("pk root", flip("sl_pk", 0, 1, &one)),
            ("randomizer", flip("sl_r", 0, 0, &one)),
            ("fors secret", flip("sl_fors", 3, 0, &one)),
            ("fors path", flip("sl_fors", 3, 7, &one)),
            ("wots digit", flip("sl_digits", 2, 5, &next)),
            ("wots chain value", flip("sl_wots", 4, 10, &one)),
            ("ht path", flip("sl_auth", 6, 8, &one)),
            ("byte", flip("bytes", 1, 3, &next)),
            ("table cell", flip("table_cells", 7, 0, &one)),
        ];
        for (label, h) in cases {
            assert!(!proves(&program, &h, pi), "{label} mutation still proves");
            println!("{label}: rejected");
        }
    }
}
