//! Falcon-512 (round 3, PQClean raw-message mode) leaf: `guests/falcon.py`.

use std::collections::BTreeMap;

use primitives::field::F192;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use tide_fn_dsa::{
    CryptoRng, FN_DSA_LOGN_512, FalconProfile, KeyPairGenerator512, RngCore, RngError, SIGN_KEY_SIZE_512,
    SIGNATURE_SIZE_512, SigningKey, SigningKeyStandard, VRFY_KEY_SIZE_512, VerifyingKey, VerifyingKeyStandard,
};

use crate::mldsa::{LANES, bit, lane_f, lanes, push_bytes};
use crate::{Claim, Hints, Scheme, cell, count, flds};

const GUEST: &str = include_str!("../guests/falcon.py");
pub const CLAIM_TAG: &[u8; 16] = b"EIP8288:fn512:v1";
pub const Q: u32 = 12289;
const N: usize = 512;
const NINV: u32 = 12265;
const NORM_BOUND: u64 = 34034726;

pub struct Falcon512;

pub struct FalconItem {
    pub pk: [u8; VRFY_KEY_SIZE_512],
    pub msg: [u8; 32],
    pub sig: Vec<u8>,
}

/// A SHAKE256 stream of a label and an index, as the signer's randomness.
struct Stream(sha3::Shake256Reader);

impl Stream {
    fn new(label: &[u8], i: usize) -> Self {
        let mut h = sha3::Shake256::default();
        h.update(label);
        h.update(&(i as u64).to_le_bytes());
        Self(h.finalize_xof())
    }
}

impl RngCore for Stream {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0; 4];
        self.0.read(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.0.read(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.read(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.0.read(dest);
        Ok(())
    }
}

impl CryptoRng for Stream {}

pub fn items(n: usize) -> Vec<FalconItem> {
    (0..n)
        .map(|i| {
            let mut seed = [0u8; 48];
            Stream::new(b"key", i).fill_bytes(&mut seed);
            let (mut sk, mut pk) = ([0; SIGN_KEY_SIZE_512], [0; VRFY_KEY_SIZE_512]);
            KeyPairGenerator512::default()
                .keygen_from_seed_pqclean(FN_DSA_LOGN_512, &seed, &mut sk, &mut pk)
                .expect("keygen");
            let mut msg = [0x42u8; 32];
            msg[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let mut sig = [0; SIGNATURE_SIZE_512];
            let len = SigningKeyStandard::decode(&sk)
                .expect("key")
                .sign_falcon(&mut Stream::new(b"sign", i), FalconProfile::PqClean, &msg, &mut sig)
                .expect("signs");
            assert!(VerifyingKeyStandard::decode(&pk).unwrap().verify_falcon(
                FalconProfile::PqClean,
                &sig[..len],
                &msg
            ));
            FalconItem {
                pk,
                msg,
                sig: sig[..len].to_vec(),
            }
        })
        .collect()
}

fn pow(b: u32, mut e: u32) -> u32 {
    let (mut acc, mut b) = (1u64, b as u64);
    while e > 0 {
        if e & 1 == 1 {
            acc = acc * b % Q as u64;
        }
        b = b * b % Q as u64;
        e >>= 1;
    }
    acc as u32
}

/// psi^brv9(m), psi = 11^12 a primitive 1024th root of unity mod q.
pub fn zetas() -> Vec<u32> {
    let psi = pow(11, 12);
    (0..N).map(|m| pow(psi, (m as u32).reverse_bits() >> 23)).collect()
}

/// Host side of the guest's mod-12289 arithmetic, pushing its hints.
pub struct Fq<'a>(pub &'a mut Hints);

impl Fq<'_> {
    pub fn mul(&mut self, a: u32, b: u32) -> u32 {
        let x = a * b;
        self.0
            .push("fq", vec![count((x % Q) as usize), count((x / Q) as usize)]);
        x % Q
    }
    fn can(&mut self, x: u32) -> u32 {
        self.0.push("fa", vec![count((x % Q) as usize)]);
        x % Q
    }
    pub fn ntt(&mut self, w: &[u32]) -> Vec<u32> {
        let z = zetas();
        let mut cur = w.to_vec();
        for layer in 0..9 {
            let len = 256 >> layer;
            let mut nxt = vec![0; N];
            for b in 0..(1 << layer) {
                let start = 2 * len * b;
                for j in start..start + len {
                    let t = self.mul(z[(1 << layer) + b], cur[j + len]);
                    nxt[j] = self.can(cur[j] + t);
                    nxt[j + len] = self.can(cur[j] + Q - t);
                }
            }
            cur = nxt;
        }
        cur
    }
    pub fn intt(&mut self, w: &[u32]) -> Vec<u32> {
        let z = zetas();
        let mut cur = w.to_vec();
        for s in 0..9 {
            let len = 1 << s;
            let mut nxt = vec![0; N];
            for b in 0..(256 >> s) {
                let start = 2 * len * b;
                for j in start..start + len {
                    nxt[j] = self.can(cur[j] + cur[j + len]);
                    let d = self.can(cur[j + len] + Q - cur[j]);
                    nxt[j + len] = self.mul(z[(512 >> s) - 1 - b], d);
                }
            }
            cur = nxt;
        }
        cur.iter().map(|&v| self.mul(NINV, v)).collect()
    }
}

/// Falcon's compressed s2 (comp_decode).
fn decode_s2(buf: &[u8]) -> Vec<i32> {
    let (mut acc, mut acc_len, mut v) = (0u32, 0u32, 0usize);
    (0..N)
        .map(|_| {
            acc = (acc << 8) | buf[v] as u32;
            v += 1;
            let b = acc >> acc_len;
            let (s, mut m) = (b & 128, (b & 127) as i32);
            loop {
                if acc_len == 0 {
                    acc = (acc << 8) | buf[v] as u32;
                    v += 1;
                    acc_len = 8;
                }
                acc_len -= 1;
                if (acc >> acc_len) & 1 != 0 {
                    break;
                }
                m += 128;
            }
            if s != 0 { -m } else { m }
        })
        .collect()
}

impl Scheme for Falcon512 {
    type Item = FalconItem;
    const NAME: &'static str = "falcon512";

    fn source() -> String {
        format!("{LANES}\n{GUEST}")
    }

    fn placeholders(ps: &mut BTreeMap<String, String>) {
        let tag = cell(CLAIM_TAG);
        ps.insert("CLAIM_TAG_0".into(), tag.c0.to_string());
        ps.insert("CLAIM_TAG_1".into(), tag.c1.to_string());
        ps.insert("FBT".into(), flds(&(0..256).map(lane_f).collect::<Vec<_>>()));
        ps.insert(
            "FZT".into(),
            flds(&zetas().iter().map(|&z| count(z as usize)).collect::<Vec<_>>()),
        );
        let ninv = count(NINV as usize);
        ps.insert("FNINV".into(), crate::f192_literal(ninv));
    }

    fn claim(item: &FalconItem) -> Claim {
        let mut bytes = CLAIM_TAG.to_vec();
        bytes.extend_from_slice(&item.msg);
        bytes.extend_from_slice(&item.pk);
        primitives::keccak::keccak256(&bytes)
    }

    fn push_hints(item: &FalconItem, hints: &mut Hints) {
        let (pk, msg, sig) = (&item.pk, &item.msg, &item.sig);
        hints.push("fa_pk", lanes(&pk[..896]).into_iter().map(lane_f).collect());
        hints.push("fa_pk_last", vec![count(pk[896] as usize)]);
        hints.push("fa_msg", lanes(msg).into_iter().map(lane_f).collect());
        let nonce = &sig[1..41];
        hints.push("fa_nonce", lanes(nonce).into_iter().map(lane_f).collect());
        assert_eq!(pk[0], 0x09);
        let mut h = Vec::with_capacity(N);
        let (mut acc, mut acc_len) = (0u32, 0);
        for &b in &pk[1..] {
            acc = (acc << 8) | b as u32;
            acc_len += 8;
            if acc_len >= 14 {
                acc_len -= 14;
                h.push((acc >> acc_len) & 0x3fff);
            }
        }

        // HashToPoint.
        let mut sh = sha3::Shake256::default();
        sh.update(nonce);
        sh.update(msg);
        let mut stream = vec![0u8; 136 * 15];
        sh.finalize_xof().read(&mut stream);
        let (mut c, mut ns) = (Vec::with_capacity(N), 0);
        while c.len() < N {
            let w = (stream[2 * ns] as u32) << 8 | stream[2 * ns + 1] as u32;
            if w < 5 * Q {
                c.push(w % Q);
            }
            ns += 1;
        }
        let nb = ns / 68 + 1;
        hints.push("htp_nb", vec![count(nb)]);
        push_bytes(hints, &stream[..136 * nb]);
        hints.push("htp_n", vec![count(ns)]);
        for s in 0..ns {
            let w = (stream[2 * s] as u32) << 8 | stream[2 * s + 1] as u32;
            hints.push("htp_acc", vec![bit(w < 5 * Q)]);
            if w < 5 * Q {
                hints.push("htp_kc", vec![count((w / Q) as usize), count((w % Q) as usize)]);
            }
        }

        // s2, s1 = c - s2 h, norms.
        let s2 = decode_s2(&sig[41..]);
        let mut norm = 0u64;
        let s2q: Vec<u32> = s2
            .iter()
            .map(|&v| {
                norm += (v * v) as u64;
                let r = v.rem_euclid(Q as i32) as u32;
                hints.push(
                    "fa_s2",
                    vec![count(v.unsigned_abs() as usize), bit(v < 0), count(r as usize)],
                );
                r
            })
            .collect();
        let mut fq = Fq(hints);
        let s2h = fq.ntt(&s2q);
        let hh = fq.ntt(&h);
        let pr: Vec<u32> = (0..N).map(|k| fq.mul(s2h[k], hh[k])).collect();
        let p = fq.intt(&pr);
        for k in 0..N {
            let r = fq.can(c[k] + Q - p[k]);
            let big = r >= 6145;
            let v = if big { Q - r } else { r } as u64;
            norm += v * v;
            fq.0.push("fa_big", vec![bit(big)]);
        }
        assert!(norm <= NORM_BOUND, "host Falcon recomputation rejects the signature");
        let slack = NORM_BOUND - norm;
        hints.push(
            "fa_slack",
            vec![count((slack & 0xffff) as usize), count((slack >> 16) as usize)],
        );
        let _ = F192::ZERO;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntt_is_negacyclic() {
        let a: Vec<u32> = (0..N as u32).map(|i| (i * 7919 + 3) % Q).collect();
        let b: Vec<u32> = (0..N as u32).map(|i| (i * 104729 + 5) % Q).collect();
        let mut hints = Hints::default();
        let mut fq = Fq(&mut hints);
        let (fa, fb) = (fq.ntt(&a), fq.ntt(&b));
        let pr: Vec<u32> = (0..N).map(|k| fq.mul(fa[k], fb[k])).collect();
        let got = fq.intt(&pr);
        let mut want = vec![0i64; N];
        for i in 0..N {
            for j in 0..N {
                let p = a[i] as i64 * b[j] as i64;
                if i + j < N {
                    want[i + j] += p
                } else {
                    want[i + j - N] -= p
                }
            }
        }
        let want: Vec<u32> = want.iter().map(|v| v.rem_euclid(Q as i64) as u32).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn host_recomputes_signatures() {
        for item in items(3) {
            Falcon512::push_hints(&item, &mut Hints::default());
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
        let program = program::<Falcon512>();
        let (_, hints, pi, _) = witness::<Falcon512>(items(1));
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
            ("message lane", flip("fa_msg", 0, 0, &one)),
            ("pk lane", flip("fa_pk", 0, 50, &one)),
            ("nonce lane", flip("fa_nonce", 0, 2, &one)),
            ("s2 sign", flip("fa_s2", 5, 1, &one)),
            ("s2 residue", flip("fa_s2", 5, 2, &next)),
            ("centering flag", flip("fa_big", 9, 0, &one)),
            ("sample flag", flip("htp_acc", 3, 0, &one)),
            ("reduction", flip("fq", 100, 0, &next)),
            ("canonical", flip("fa", 100, 0, &next)),
            ("norm slack", flip("fa_slack", 0, 0, &next)),
        ];
        for (label, h) in cases {
            assert!(!proves(&program, &h, pi), "{label} mutation still proves");
            println!("{label}: rejected");
        }
    }
}
