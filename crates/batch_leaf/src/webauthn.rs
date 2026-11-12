//! ML-DSA-44 inside a WebAuthn assertion (COSE alg -48): `guests/mldsa_webauthn.py`.

use std::collections::BTreeMap;

use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use primitives::field::F192;
use sha2::Digest;

use crate::mldsa::{ARITH, LANES, lane_f, lanes, push_bytes, push_core_hints};
use crate::{Claim, Hints, Scheme, cell, count, flds};

const CORE: &str = include_str!("../guests/mldsa.py");
const SHA: &str = include_str!("../guests/sha256.py");
const GUEST: &str = include_str!("../guests/mldsa_webauthn.py");
pub const CLAIM_TAG: &[u8; 16] = b"EIP8288:mldsa:wa";
const PREFIX: &[u8; 36] = br#"{"type":"webauthn.get","challenge":""#;
pub const RP_ID: &str = "wallet.example.org";
const FLAGS: u8 = 0x05;
const POLICY: u8 = 0x05;

pub struct MlDsa44WebAuthn;

pub struct WebAuthnItem {
    pub pk: [u8; ml_dsa_44::PK_LEN],
    pub challenge: [u8; 32],
    pub rp_id_hash: [u8; 32],
    pub sign_count: u32,
    pub client_data_json: Vec<u8>,
    pub sig: [u8; ml_dsa_44::SIG_LEN],
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn base64url(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let v = chunk
            .iter()
            .enumerate()
            .fold(0u32, |a, (i, &b)| a | (b as u32) << (16 - 8 * i));
        for k in 0..chunk.len() + 1 {
            out.push(B64[(v >> (18 - 6 * k) & 63) as usize] as char);
        }
    }
    out
}

fn auth_data(item: &WebAuthnItem) -> Vec<u8> {
    let mut a = item.rp_id_hash.to_vec();
    a.push(FLAGS);
    a.extend_from_slice(&item.sign_count.to_be_bytes());
    a
}

fn signed_message(item: &WebAuthnItem) -> Vec<u8> {
    let mut m = auth_data(item);
    m.extend_from_slice(&sha2::Sha256::digest(&item.client_data_json));
    m
}

/// `n` credentials, each asserting its own challenge for one relying party.
pub fn items(n: usize) -> Vec<WebAuthnItem> {
    (0..n)
        .map(|i| {
            let mut seed = [0x77u8; 32];
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let (pk, sk) = ml_dsa_44::KG::keygen_from_seed(&seed);
            let mut challenge = [0xc4u8; 32];
            challenge[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let cdj = format!(
                r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://{RP_ID}","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}}"#,
                base64url(&challenge)
            );
            let mut item = WebAuthnItem {
                pk: pk.clone().into_bytes(),
                challenge,
                rp_id_hash: sha2::Sha256::digest(RP_ID.as_bytes()).into(),
                sign_count: 1000 + i as u32,
                client_data_json: cdj.into_bytes(),
                sig: [0; ml_dsa_44::SIG_LEN],
            };
            item.sig = sk.try_sign_with_seed(&seed, &signed_message(&item), &[]).expect("signs");
            assert!(pk.verify(&signed_message(&item), &item.sig, &[]));
            item
        })
        .collect()
}

fn b64_tables() -> Vec<F192> {
    let mut t = vec![F192::ZERO; 7 * 256];
    for (v, &c) in B64.iter().enumerate() {
        t[c as usize] = F192::ONE;
        for k in 0..6 {
            if (v >> k) & 1 == 1 {
                t[256 * (1 + k) + c as usize] = F192::ONE;
            }
        }
    }
    t
}

fn kt_cells() -> Vec<F192> {
    crate::sha256::K_PUB.iter().map(|&k| count(k as usize)).collect()
}

impl Scheme for MlDsa44WebAuthn {
    type Item = WebAuthnItem;
    const NAME: &'static str = "mldsa44wa";

    fn source() -> String {
        format!("FINV_REC = FINV_REC_PLACEHOLDER\n{ARITH}\n{LANES}\n{CORE}\n{SHA}\n{GUEST}")
    }

    fn placeholders(ps: &mut BTreeMap<String, String>) {
        crate::mldsa::MlDsa44::placeholders(ps);
        let tag = cell(CLAIM_TAG);
        ps.insert("WA_TAG_0".into(), tag.c0.to_string());
        ps.insert("WA_TAG_1".into(), tag.c1.to_string());
        ps.insert(
            "WA_PREFIX".into(),
            flds(&PREFIX.iter().map(|&b| count(b as usize)).collect::<Vec<_>>()),
        );
        ps.insert("WA_QUOTE".into(), crate::f192_literal(count(b'"' as usize)));
        crate::checked_placeholders(ps, "WA_B64", &b64_tables());
        crate::checked_placeholders(ps, "WA_KT", &kt_cells());
        ps.insert("SHA_IVG".into(), crate::sha256::gpow_list(&crate::sha256::IV));
    }

    fn setup_hints(hints: &mut Hints) {
        crate::mldsa::MlDsa44::setup_hints(hints);
        crate::push_checked(hints, &b64_tables());
        crate::push_checked(hints, &kt_cells());
    }

    fn claim(item: &WebAuthnItem) -> Claim {
        let mut b = CLAIM_TAG.to_vec();
        b.extend_from_slice(&item.pk);
        b.extend_from_slice(&item.challenge);
        b.extend_from_slice(&item.rp_id_hash);
        let mut policy = [0u8; 16];
        policy[0] = POLICY;
        b.extend_from_slice(&policy);
        primitives::keccak::keccak256(&b)
    }

    fn push_hints(item: &WebAuthnItem, hints: &mut Hints) {
        hints.push("ml_pk", lanes(&item.pk).into_iter().map(lane_f).collect());
        hints.push(
            "wa_challenge",
            vec![cell(&item.challenge[..16]), cell(&item.challenge[16..])],
        );
        hints.push(
            "wa_rp",
            vec![cell(&item.rp_id_hash[..16]), cell(&item.rp_id_hash[16..])],
        );
        let cdj = &item.client_data_json;
        let l = cdj.len();
        let nb = (l + 9).div_ceil(64);
        hints.push("wa_nb", vec![count(nb)]);
        hints.push("wa_len", vec![count(l)]);
        let mut padded = cdj.clone();
        padded.push(0x80);
        padded.resize(64 * nb - 8, 0);
        padded.extend_from_slice(&(8 * l as u64).to_be_bytes());
        let mut st = crate::sha256::IV;
        for block in padded.chunks(64) {
            hints.push("wa_bytes", block.iter().map(|&b| count(b as usize)).collect());
            let words: [u32; 16] =
                std::array::from_fn(|i| u32::from_be_bytes(block[4 * i..4 * i + 4].try_into().unwrap()));
            st = crate::sha256::compress(hints, st, words);
        }
        let digest: Vec<u8> = st.iter().flat_map(|w| w.to_be_bytes()).collect();
        assert_eq!(digest[..], sha2::Sha256::digest(cdj)[..]);
        push_bytes(hints, &item.rp_id_hash);
        hints.push(
            "wa_flags",
            (0..8).map(|i| crate::mldsa::bit((FLAGS >> i) & 1 == 1)).collect(),
        );
        hints.push(
            "wa_count",
            item.sign_count
                .to_be_bytes()
                .iter()
                .map(|&b| count(b as usize))
                .collect(),
        );
        push_core_hints(&item.pk, &signed_message(item), &item.sig, hints);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_matches_known_answers() {
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn host_recomputes_assertions() {
        for item in items(2) {
            MlDsa44WebAuthn::push_hints(&item, &mut Hints::default());
            assert!(
                (150..=250).contains(&item.client_data_json.len()),
                "{}",
                item.client_data_json.len()
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
        let program = program::<MlDsa44WebAuthn>();
        let (_, hints, pi, _) = witness::<MlDsa44WebAuthn>(items(1));
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
            ("challenge cell", flip("wa_challenge", 0, 1, &one)),
            ("rpIdHash cell", flip("wa_rp", 0, 0, &one)),
            ("type byte", flip("wa_bytes", 0, 12, &next)),
            ("challenge character", flip("wa_bytes", 0, 40, &next)),
            ("origin byte", flip("wa_bytes", 1, 30, &next)),
            ("length", flip("wa_len", 0, 0, &next)),
            ("UV flag", flip("wa_flags", 0, 2, &one)),
            ("sign count", flip("wa_count", 0, 3, &next)),
            ("sha carry", flip("sha_c", 50, 0, &next)),
        ];
        for (label, h) in cases {
            assert!(!proves(&program, &h, pi), "{label} mutation still proves");
            println!("{label}: rejected");
        }
    }
}
