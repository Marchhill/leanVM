//! The empty scheme: claims without signatures, isolating the batch statement.

use std::collections::BTreeMap;

use crate::{Claim, Hints, Scheme, cell};

pub struct Null;

impl Scheme for Null {
    type Item = Claim;
    const NAME: &'static str = "null";

    fn source() -> String {
        include_str!("../guests/null_claim.py").to_string()
    }

    fn placeholders(_: &mut BTreeMap<String, String>) {}

    fn claim(item: &Claim) -> Claim {
        *item
    }

    fn push_hints(item: &Claim, hints: &mut Hints) {
        hints.push("claim", vec![cell(&item[..16]), cell(&item[16..])]);
    }
}

/// `n` distinct pseudo-random claims.
pub fn items(n: usize) -> Vec<Claim> {
    (0..n as u64)
        .map(|i| primitives::keccak::keccak256(&i.to_le_bytes()))
        .collect()
}
