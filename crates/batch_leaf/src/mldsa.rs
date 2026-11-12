//! ML-DSA-44 (FIPS 204) leaf: `guests/mldsa.py` over `guests/mldsa_arith.py`.
//!
//! The host decodes the key and signature, recomputes every intermediate the guest
//! checks, and pushes the hints in the guest's execution order.

use std::collections::BTreeMap;

use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use primitives::field::F192;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::mq::{self, Mq, Q};
use crate::{Claim, Hints, Scheme, cell, count, flds};

pub const ARITH: &str = include_str!("../guests/mldsa_arith.py");
const GUEST: &str = include_str!("../guests/mldsa.py");
const PLAIN: &str = include_str!("../guests/mldsa_plain.py");
pub const LANES: &str = include_str!("../guests/lanes.py");

pub const CLAIM_TAG: &[u8; 16] = b"EIP8288:mldsa:v2";
const GAMMA1: i32 = 1 << 17;
const GAMMA2: u32 = 95232;
const BETA: i32 = 78;
const OMEGA: usize = 80;
const TAU: usize = 39;

pub struct MlDsa44;

pub struct MlDsaItem {
    pub pk: [u8; ml_dsa_44::PK_LEN],
    pub msg: Vec<u8>,
    pub sig: [u8; ml_dsa_44::SIG_LEN],
}

/// Longest message the leaf accepts: M' = 0x00 0x00 || M fills at most MSG_LANES - 1 whole lanes
/// and a partial one.
pub const MAX_MSG: usize = 8 * 64 - 3;

/// A WebAuthn-shaped message: authenticatorData (rpIdHash, flags, signCount) || SHA-256(clientDataJSON).
pub fn passkey_message(i: usize) -> Vec<u8> {
    use sha2::Digest;
    let mut m = sha2::Sha256::digest(b"wallet.example.org").to_vec();
    m.push(0x05);
    m.extend_from_slice(&(1000 + i as u32).to_be_bytes());
    let cdj = format!(
        r#"{{"type":"webauthn.get","challenge":"{i:043}","origin":"https://wallet.example.org","crossOrigin":false}}"#
    );
    m.extend_from_slice(&sha2::Sha256::digest(cdj.as_bytes()));
    m
}

/// `n` distinct keys, each signing a 69-byte passkey message (deterministic).
pub fn items(n: usize) -> Vec<MlDsaItem> {
    items_with(n, &passkey_message)
}

/// `n` distinct keys, each signing a `len`-byte message.
pub fn items_len(n: usize, len: usize) -> Vec<MlDsaItem> {
    items_with(n, &|i| {
        (0..len).map(|k| (k as u8) ^ (i as u8).wrapping_mul(37)).collect()
    })
}

pub fn items_with(n: usize, message: &dyn Fn(usize) -> Vec<u8>) -> Vec<MlDsaItem> {
    (0..n)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let (pk, sk) = ml_dsa_44::KG::keygen_from_seed(&seed);
            let msg = message(i);
            assert!(msg.len() <= MAX_MSG);
            let sig = sk.try_sign_with_seed(&seed, &msg, &[]).expect("signs");
            assert!(pk.verify(&msg, &sig, &[]));
            MlDsaItem {
                pk: pk.into_bytes(),
                msg,
                sig,
            }
        })
        .collect()
}

pub fn shake256(data: &[&[u8]], out: &mut [u8]) {
    let mut h = sha3::Shake256::default();
    for d in data {
        h.update(d);
    }
    h.finalize_xof().read(out);
}

pub fn lanes(bytes: &[u8]) -> Vec<u64> {
    bytes
        .chunks(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect()
}

pub fn lane_f(l: u64) -> F192 {
    F192::new(l, 0, 0)
}

pub fn bit(b: bool) -> F192 {
    if b { F192::ONE } else { F192::ZERO }
}

pub fn push_bytes(hints: &mut Hints, bytes: &[u8]) {
    for chunk in bytes.chunks(8) {
        hints.push("bytes", chunk.iter().map(|&b| count(b as usize)).collect());
    }
}

/// FIPS 204 Decompose then UseHint.
fn use_hint(h: bool, r: u32) -> u32 {
    let alpha = 2 * GAMMA2;
    let mut r0 = (r % alpha) as i64;
    if r0 > (alpha / 2) as i64 {
        r0 -= alpha as i64;
    }
    let (r1, r0) = if r as i64 - r0 == (Q - 1) as i64 {
        (0i64, r0 - 1)
    } else {
        ((r as i64 - r0) / alpha as i64, r0)
    };
    match (h, r0 > 0) {
        (false, _) => r1 as u32,
        (true, true) => ((r1 + 1).rem_euclid(44)) as u32,
        (true, false) => ((r1 - 1).rem_euclid(44)) as u32,
    }
}

/// UseHint's value at index 4 t + 2 [s = 0] + h, then its split patterns.
fn w_tables() -> Vec<F192> {
    let mut full = vec![0u64; 356];
    for t in 0..89u32 {
        for z in 0..2u32 {
            for h in 0..2u32 {
                let r = t * GAMMA2 + (1 - z);
                full[(4 * t + 2 * z + h) as usize] = if r < Q { use_hint(h == 1, r) as u64 } else { 0 };
            }
        }
    }
    let parts: [fn(u64) -> u64; 5] = [|v| v, |v| v & 15, |v| v >> 4, |v| v & 3, |v| v >> 2];
    parts
        .iter()
        .flat_map(|f| full.iter().map(move |&v| lane_f(f(v))))
        .collect()
}

/// RejNTTPoly(rho || s || r): the polynomial, blocks squeezed, candidates read, stream.
fn rej_ntt_poly(rho: &[u8], s: u8, r: u8) -> ([u32; 256], usize, usize, Vec<u8>) {
    let mut h = sha3::Shake128::default();
    h.update(rho);
    h.update(&[s, r]);
    let mut stream = vec![0u8; 168 * 8];
    h.finalize_xof().read(&mut stream);
    let mut out = [0u32; 256];
    let (mut n, mut c) = (0, 0);
    while n < 256 {
        let v = stream[3 * c] as u32 | (stream[3 * c + 1] as u32) << 8 | ((stream[3 * c + 2] & 0x7f) as u32) << 16;
        if v < Q {
            out[n] = v;
            n += 1;
        }
        c += 1;
    }
    (out, c / 56 + 1, c, stream)
}

fn zt_cells() -> Vec<F192> {
    mq::zetas().iter().flat_map(|&z| mq::record(z)).collect()
}

pub fn bt_cells() -> Vec<F192> {
    (0..256).map(lane_f).collect()
}

impl Scheme for MlDsa44 {
    type Item = MlDsaItem;
    const NAME: &'static str = "mldsa44";

    fn source() -> String {
        format!("FINV_REC = FINV_REC_PLACEHOLDER\n{ARITH}\n{LANES}\n{GUEST}\n{PLAIN}")
    }

    fn placeholders(ps: &mut BTreeMap<String, String>) {
        crate::checked_placeholders(ps, "ZT", &zt_cells());
        ps.insert("FINV_REC".into(), mq::records(&[mq::FINV]));
        let tag = cell(CLAIM_TAG);
        ps.insert("CLAIM_TAG_0".into(), tag.c0.to_string());
        ps.insert("CLAIM_TAG_1".into(), tag.c1.to_string());
        crate::checked_placeholders(ps, "BT", &bt_cells());
        let crv = [0, 1, 0, 0, 0, 2046, 0, 1, (Q - 1) as usize].map(count);
        ps.insert("CRV".into(), flds(&crv));
        crate::checked_placeholders(ps, "WT", &w_tables());
    }

    fn setup_hints(hints: &mut Hints) {
        crate::push_checked(hints, &zt_cells());
        crate::push_checked(hints, &bt_cells());
        crate::push_checked(hints, &w_tables());
    }

    fn claim(item: &MlDsaItem) -> Claim {
        let mut bytes = CLAIM_TAG.to_vec();
        bytes.extend_from_slice(&item.pk);
        bytes.extend_from_slice(&(item.msg.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&item.msg);
        primitives::keccak::keccak256(&bytes)
    }

    fn push_hints(item: &MlDsaItem, hints: &mut Hints) {
        hints.push("ml_pk", lanes(&item.pk).into_iter().map(lane_f).collect());
        let mut mp = vec![0u8, 0];
        mp.extend_from_slice(&item.msg);
        let (nq, r) = (mp.len() / 8, mp.len() % 8);
        hints.push("ml_mlen", vec![count(nq), count(r)]);
        for lane in lanes(&mp[..8 * nq]) {
            hints.push("ml_mlane", vec![lane_f(lane)]);
        }
        let mut part = [0u8; 8];
        part[..r].copy_from_slice(&mp[8 * nq..]);
        hints.push("ml_mpart", vec![lane_f(u64::from_le_bytes(part))]);
        push_bytes(hints, &part);
        if nq > 0 {
            push_bytes(hints, &mp[..8]);
        }
        // the two sponges' block splits: claim (167 lanes before M'), then mu (8)
        for before in [167, 8] {
            let q = before + nq;
            hints.push("sv_split", vec![count(q / 17), count(q % 17)]);
        }
        push_core_hints(&item.pk, &item.msg, &item.sig, hints);
    }
}

/// The hints of `mldsa_core` for a signature on `msg`, after the caller's own.
pub fn push_core_hints(pk: &[u8], msg: &[u8], sig: &[u8], hints: &mut Hints) {
    {
        let mut tr = [0u8; 64];
        shake256(&[pk], &mut tr);
        let mut mu = [0u8; 64];
        shake256(&[&tr, &[0, 0], msg], &mut mu);

        // SampleInBall.
        let ctilde = &sig[..32];
        hints.push("ml_ctilde", lanes(ctilde).into_iter().map(lane_f).collect());
        let mut sb = [0u8; 136];
        shake256(&[ctilde], &mut sb);
        push_bytes(hints, &sb[8..]);
        let signs = u64::from_le_bytes(sb[..8].try_into().unwrap());
        let (mut entries, mut cursor) = (Vec::<(usize, bool)>::new(), 8);
        for t in 0..TAU {
            let i = 256 - TAU + t;
            let mut skip = 0;
            while sb[cursor + skip] as usize > i {
                skip += 1;
            }
            let j = sb[cursor + skip] as usize;
            cursor += skip + 1;
            assert!(cursor <= 136, "SampleInBall needs a second block");
            hints.push("sib_skip", vec![count(skip)]);
            let hit = entries.iter().position(|e| e.0 == j);
            if let Some(e) = hit {
                entries[e].0 = i;
            }
            hints.push("sib_hit", vec![count(hit.unwrap_or(t))]);
            entries.push((j, (signs >> t) & 1 == 1));
        }
        let mut c = [0u32; 256];
        let mut codes = vec![count(0); 256];
        for &(p, neg) in &entries {
            c[p] = if neg { Q - 1 } else { 1 };
            codes[p] = count(if neg { 2 } else { 1 });
        }
        hints.push("sib_codes", codes);

        // z.
        let zbytes = &sig[32..32 + 2304];
        let mut z = vec![0u32; 1024];
        for (k, zk) in z.iter_mut().enumerate() {
            let mut v = 0u32;
            for b in 0..18 {
                let p = 18 * k + b;
                v |= ((zbytes[p / 8] >> (p % 8)) & 1) as u32 * (1 << b);
            }
            let zi = GAMMA1 - v as i32;
            assert!(zi.abs() < GAMMA1 - BETA);
            let m = zi.unsigned_abs();
            *zk = zi.rem_euclid(Q as i32) as u32;
            hints.push(
                "ml_z",
                vec![
                    count((m & 0xffff) as usize),
                    bit(m >> 16 == 1),
                    bit(zi < 0),
                    count((*zk % 4096) as usize),
                    count((*zk / 4096) as usize),
                ],
            );
        }

        // t1 2^13, and A_hat.
        let t1: Vec<u32> = (0..1024)
            .map(|k| {
                let mut v = 0u32;
                for b in 0..10 {
                    let p = 256 + 10 * k + b;
                    v |= ((pk[p / 8] >> (p % 8)) & 1) as u32 * (1 << b);
                }
                v << 13
            })
            .collect();
        let mut a_hat = vec![[0u32; 256]; 16];
        for r in 0..4u8 {
            for s in 0..4u8 {
                let (poly, nb, ncand, stream) = rej_ntt_poly(&pk[..32], s, r);
                hints.push("rej_nb", vec![count(nb)]);
                push_bytes(hints, &stream[..168 * nb]);
                hints.push("rej_n", vec![count(ncand)]);
                for cidx in 0..ncand {
                    let (b1, b2) = (stream[3 * cidx + 1], stream[3 * cidx + 2]);
                    hints.push(
                        "rej_split",
                        vec![
                            count((b1 & 15) as usize),
                            count((b1 >> 4) as usize),
                            count((b2 & 127) as usize),
                            bit(b2 >> 7 == 1),
                        ],
                    );
                    let v = stream[3 * cidx] as u32 | (b1 as u32) << 8 | ((b2 & 0x7f) as u32) << 16;
                    hints.push("rej_acc", vec![bit(v < Q)]);
                    if v < Q {
                        let r1 = (v >> 12) as usize;
                        let wy = if r1 == 2046 {
                            F192::ZERO
                        } else {
                            (count(r1) + count(2046)).inv()
                        };
                        hints.push("rej_wy", vec![wy]);
                    }
                }
                a_hat[(4 * r + s) as usize] = poly;
            }
        }

        // NTTs and rows, in the guest's order.
        let mut mq = Mq(hints);
        let poly = |v: &[u32]| -> [u32; 256] { v.try_into().unwrap() };
        let zh: Vec<[u32; 256]> = (0..4).map(|i| mq.ntt(&poly(&z[256 * i..256 * (i + 1)]))).collect();
        let ch = mq.ntt(&c);
        let th: Vec<[u32; 256]> = (0..4).map(|i| mq.ntt(&poly(&t1[256 * i..256 * (i + 1)]))).collect();
        let mut w = vec![0u32; 1024];
        for j in 0..4 {
            let mut acc = [0u32; 256];
            for k in 0..256 {
                let mut x = Q as u64 * (1 << 24);
                for i in 0..4 {
                    x += a_hat[4 * j + i][k] as u64 * zh[i][k] as u64;
                }
                x -= ch[k] as u64 * th[j][k] as u64;
                acc[k] = mq.wide(x);
            }
            w[256 * j..256 * (j + 1)].copy_from_slice(&mq.intt(&acc));
        }

        // h, UseHint, w1Encode, and the c~ check.
        let hb = &sig[32 + 2304..];
        let mut h = vec![false; 1024];
        let mut index = 0usize;
        for i in 0..4 {
            let end = hb[OMEGA + i] as usize;
            while index < end {
                h[256 * i + hb[index] as usize] = true;
                index += 1;
            }
        }
        hints.push("ml_h", h.iter().map(|&b| bit(b)).collect());
        let mut w1enc = vec![0u8; 768];
        for k in 0..1024 {
            let r = w[k];
            let (t, s) = (r / GAMMA2, r % GAMMA2);
            let wz = if s == 0 {
                F192::ZERO
            } else {
                (count(s as usize) + F192::ONE).inv()
            };
            let wy = if t == 88 {
                F192::ZERO
            } else {
                (count(t as usize) + count(88)).inv()
            };
            hints.push(
                "uh",
                vec![
                    count(t as usize),
                    count((s & 0xffff) as usize),
                    bit(s >> 16 == 1),
                    bit(s == 0),
                    wz,
                    wy,
                ],
            );
            let v = use_hint(h[k], r);
            for b in 0..6 {
                let p = 6 * k + b;
                w1enc[p / 8] |= (((v >> b) & 1) as u8) << (p % 8);
            }
        }
        let mut ct2 = [0u8; 32];
        shake256(&[&mu, &w1enc], &mut ct2);
        assert_eq!(&ct2, ctilde, "host ML-DSA recomputation disagrees with the signature");
    }
}

impl Mq<'_> {
    /// A product sum below 2^49, reduced with the wide quotient.
    pub fn wide(&mut self, x: u64) -> u32 {
        let (qq, r) = ((x / Q as u64) as usize, (x % Q as u64) as usize);
        self.0.push("mq", vec![count(r % 4096), count(r / 4096)]);
        self.0.push("mqq", vec![count(qq % 4096), count(qq / 4096)]);
        r as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pure ML-DSA-44 with an empty context over authenticatorData || SHA-256(clientDataJSON),
    /// the COSE -48 / WebAuthn passkey form, signed and verified by the fips204 crate.
    #[test]
    fn passkey_vector() {
        let item = &items(1)[0];
        assert_eq!(item.msg.len(), 69);
        let pk = ml_dsa_44::PublicKey::try_from_bytes(item.pk).unwrap();
        assert!(pk.verify(&item.msg, &item.sig, &[]));
        assert!(!pk.verify(&item.msg, &item.sig, b"ctx"));
        MlDsa44::push_hints(item, &mut Hints::default());
    }

    #[test]
    fn host_recomputes_any_length() {
        for len in [0, 5, 6, 32, 69, 300, MAX_MSG] {
            for item in items_len(1, len) {
                MlDsa44::push_hints(&item, &mut Hints::default());
            }
        }
    }

    #[test]
    #[ignore]
    fn leaf_proves_edge_lengths() {
        let program = crate::program::<MlDsa44>();
        for len in [0, 5, 6, 300, MAX_MSG] {
            let m = crate::prove_leaf::<MlDsa44>(&program, items_len(1, len));
            println!("len {len}: {} cycles", m.stats.base_counts.iter().sum::<usize>());
        }
    }

    #[test]
    fn host_recomputes_signatures() {
        for item in items(3) {
            let mut h = Hints::default();
            MlDsa44::push_hints(&item, &mut h);
        }
    }
}

#[cfg(test)]
mod soundness {
    use super::*;
    use crate::{count, program, witness};

    fn proves(program: &lean_vm::cpu::Program, hints: &Hints, pi: [F192; 2]) -> bool {
        let mut program = program.clone();
        for (name, entries) in &hints.0 {
            program.set_witness(name.clone(), entries.clone());
        }
        let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            lean_vm::cpu::prove(&program, pi, 1)
                .ok()
                .is_some_and(|(proof, _)| lean_vm::cpu::verify(&program, &pi, &proof).is_ok())
        }));
        run.unwrap_or(false)
    }

    /// Each mutation of an honest witness must stop the proof.
    #[test]
    #[ignore]
    fn mutated_witnesses_do_not_prove() {
        let program = program::<MlDsa44>();
        let (_, hints, pi, _) = witness::<MlDsa44>(items(1));
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
            ("message lane", flip("ml_mlane", 3, 0, &one)),
            (
                "message tail",
                flip("ml_mpart", 0, 0, &|x: F192| x + F192::new(1 << 60, 0, 0)),
            ),
            ("message length", flip("ml_mlen", 0, 1, &next)),
            ("pk lane", flip("ml_pk", 0, 100, &one)),
            ("c~ lane", flip("ml_ctilde", 0, 0, &one)),
            ("z sign", flip("ml_z", 5, 2, &one)),
            ("z magnitude", flip("ml_z", 5, 0, &next)),
            ("hint bit", flip("ml_h", 0, 3, &one)),
            ("usehint t", flip("uh", 7, 0, &next)),
            ("usehint zero flag", flip("uh", 7, 3, &one)),
            ("rejection flag", flip("rej_acc", 3, 0, &one)),
            ("sample hit", flip("sib_hit", 20, 0, &next)),
            ("sample code", flip("sib_codes", 0, 0, &next)),
            ("reduction remainder", flip("mq", 100, 0, &next)),
            ("canonical remainder", flip("ma", 100, 0, &next)),
            ("byte", flip("bytes", 10, 0, &next)),
            // validity constraints on non-canonical witnesses
            ("z at the bound gamma1 - beta", {
                let mut h = Hints(hints.0.clone());
                let e = &mut h.0.get_mut("ml_z").unwrap()[5];
                e[0] = count(65458);
                e[1] = F192::ONE;
                h
            }),
            ("hint weight omega + 1", {
                let mut h = Hints(hints.0.clone());
                let e = &mut h.0.get_mut("ml_h").unwrap()[0];
                let mut set = e.iter().filter(|&&b| b == F192::ONE).count();
                for b in e.iter_mut() {
                    if set <= 80 && *b == F192::ZERO {
                        *b = F192::ONE;
                        set += 1;
                    }
                }
                h
            }),
        ];
        for (label, h) in cases {
            assert!(!proves(&program, &h, pi), "{label} mutation still proves");
            println!("{label}: rejected");
        }
    }
}
