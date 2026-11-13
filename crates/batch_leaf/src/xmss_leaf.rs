//! leanXMSS over BLAKE2s, the prover's native hash: the hash-based baseline.

use std::collections::BTreeMap;

use primitives::field::F192;
use xmss::{Epoch, Message, XmssPublicKey, XmssSignature};

use crate::{Claim, Hints, Scheme, cell, count, dsl_u128, flds};

pub const CLAIM_TAG: &[u8; 16] = b"EIP8288:xmss:v1\0";

pub struct Xmss;

pub struct XmssItem {
    pub pk: XmssPublicKey,
    pub epoch: Epoch,
    pub message: Message,
    pub sig: XmssSignature,
}

fn tweak_cell(tweak_type: u8, sub_position: u32) -> F192 {
    cell(&xmss::make_tweak(tweak_type, sub_position, 0))
}

fn epoch_cell(epoch: Epoch) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&(epoch as u64).to_le_bytes());
    out
}

impl Scheme for Xmss {
    type Item = XmssItem;
    const NAME: &'static str = "xmss";

    fn source() -> String {
        let mut s = crate::guest_section(
            "# ---------------------------------------------------------- XMSS (host-supplied)",
            "# ------------------------------------------------------ SPHINCS+",
        );
        s.push_str("Y_TOWER = Y_TOWER_PLACEHOLDER\n");
        s.push_str(include_str!("../guests/xmss_claim.py"));
        for f in ["order_children", "fill_xmss_epoch_tables", "verify_sig", "walk"] {
            s.push_str("\n\n");
            s.push_str(&crate::guest_function(f));
        }
        s
    }

    fn placeholders(ps: &mut BTreeMap<String, String>) {
        let mut put = |k: &str, v: String| {
            ps.insert(k.to_string(), v);
        };
        put("CLAIM_TAG", dsl_u128(cell(CLAIM_TAG)).to_string());
        put("Y_TOWER", dsl_u128(F192::new(0, 1, 0)).to_string());
        put("V", xmss::V.to_string());
        put("W", xmss::W.to_string());
        put("TARGET_SUM", xmss::TARGET_SUM.to_string());
        put("LOG_LIFETIME", xmss::LOG_LIFETIME.to_string());
        put(
            "XM_ENC_TWEAK",
            dsl_u128(tweak_cell(xmss::TWEAK_TYPE_ENCODING, 0)).to_string(),
        );
        put(
            "XM_PK_TWEAK",
            dsl_u128(tweak_cell(xmss::TWEAK_TYPE_WOTS_PK, 0)).to_string(),
        );
        let chain: Vec<F192> = (0..xmss::V)
            .flat_map(|i| {
                (0..xmss::CHAIN_LENGTH - 1)
                    .map(move |s| tweak_cell(xmss::TWEAK_TYPE_CHAIN, (i * xmss::CHAIN_LENGTH + s) as u32))
            })
            .collect();
        put("XM_CHAIN_TWEAKS", flds(&chain));
        let merkle: Vec<F192> = (0..xmss::LOG_LIFETIME)
            .map(|l| tweak_cell(xmss::TWEAK_TYPE_MERKLE, (l + 1) as u32))
            .collect();
        put("XM_MERKLE_TWEAKS", flds(&merkle));
        let weights: Vec<F192> = (0..xmss::LOG_LIFETIME)
            .map(|b| cell(&xmss::make_tweak(0, 0, 1 << b)) + cell(&xmss::make_tweak(0, 0, 0)))
            .collect();
        put("XM_INDEX_WEIGHT", flds(&weights));
    }

    fn claim(item: &XmssItem) -> Claim {
        let mut bytes = CLAIM_TAG.to_vec();
        bytes.extend_from_slice(&item.pk.merkle_root);
        bytes.extend_from_slice(&item.pk.public_param);
        bytes.extend_from_slice(&item.message);
        bytes.extend_from_slice(&epoch_cell(item.epoch));
        primitives::keccak::keccak256(&bytes)
    }

    fn push_hints(item: &XmssItem, hints: &mut Hints) {
        hints.push("pk", vec![cell(&item.pk.merkle_root), cell(&item.pk.public_param)]);
        hints.push("msg", vec![cell(&item.message[..16]), cell(&item.message[16..])]);
        hints.push("epoch", vec![F192::new(item.epoch as u64, 0, 0)]);
        let wots = &item.sig.wots_signature;
        let encoding = xmss::wots_encode(&item.message, item.epoch, &item.pk.public_param, &wots.randomness)
            .expect("valid signature");
        let mut randomness = [0u8; xmss::STATE_LEN];
        randomness[..xmss::RANDOMNESS_LEN].copy_from_slice(&wots.randomness);
        hints.push("rand", vec![cell(&randomness[..16]), cell(&randomness[16..])]);
        for &e in &encoding {
            hints.push("digits", vec![count(e as usize)]);
        }
        for tip in &wots.chain_tips {
            hints.push("chain_starts", vec![cell(tip)]);
        }
        for sibling in &item.sig.merkle_proof {
            hints.push("siblings", vec![cell(sibling)]);
        }
    }
}

/// `n` distinct cached signers at one epoch and message.
pub fn items(n: usize) -> Vec<XmssItem> {
    rec_aggregation::signers_cache::get_signers(n)
        .into_iter()
        .map(|(pk, sig)| XmssItem {
            pk,
            epoch: rec_aggregation::signers_cache::XMSS_EPOCH_A,
            message: rec_aggregation::signers_cache::message(),
            sig,
        })
        .collect()
}
