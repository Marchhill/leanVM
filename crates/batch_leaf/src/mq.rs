//! Host side of `guests/mldsa_arith.py`: arithmetic mod q = 8380417 that computes each
//! value natively and pushes the hints the guest pops, in the guest's execution order.

use primitives::field::F192;

use crate::{Hints, count, flds};

pub const Q: u32 = 8380417;
const LIMB: u32 = 4096;

/// FIPS 204 `zetas[m] = 1753^brv8(m) mod q`.
pub fn zetas() -> [u32; 256] {
    let mut out = [0u32; 256];
    for (m, z) in out.iter_mut().enumerate() {
        let e = (m as u8).reverse_bits() as u64;
        *z = pow(1753, e);
    }
    out
}

pub fn pow(base: u32, mut e: u64) -> u32 {
    let (mut acc, mut b) = (1u64, base as u64 % Q as u64);
    while e > 0 {
        if e & 1 == 1 {
            acc = acc * b % Q as u64;
        }
        b = b * b % Q as u64;
        e >>= 1;
    }
    acc as u32
}

/// The three cells of a record holding `r`.
pub fn record(r: u32) -> [F192; 3] {
    assert!(r < 2047 * LIMB);
    [
        count((r % LIMB) as usize),
        count((r / LIMB) as usize),
        count(r as usize),
    ]
}

/// A list literal of records, cell by cell.
pub fn records(values: &[u32]) -> String {
    flds(&values.iter().flat_map(|&v| record(v)).collect::<Vec<_>>())
}

fn limbs(r: u32) -> [F192; 2] {
    [count((r % LIMB) as usize), count((r / LIMB) as usize)]
}

pub struct Mq<'a>(pub &'a mut Hints);

impl Mq<'_> {
    pub fn load(&mut self, r: u32) -> u32 {
        self.0.push("mv", limbs(r).to_vec());
        r
    }

    pub fn mul(&mut self, a: u32, b: u32) -> u32 {
        let x = a as u64 * b as u64;
        let (qq, r) = ((x / Q as u64) as u32, (x % Q as u64) as u32);
        self.0.push("mq", limbs(r).to_vec());
        self.0.push("mqq", limbs(qq).to_vec());
        r
    }

    fn canon(&mut self, x: u64) -> u32 {
        let r = (x % Q as u64) as u32;
        self.0.push("ma", limbs(r).to_vec());
        r
    }

    pub fn add(&mut self, a: u32, b: u32) -> u32 {
        self.canon(a as u64 + b as u64)
    }

    pub fn sub(&mut self, a: u32, b: u32) -> u32 {
        self.canon(a as u64 + 2 * Q as u64 - b as u64)
    }

    /// FIPS 204 NTT in the guest's order: layer, block, then j.
    pub fn ntt(&mut self, w: &[u32; 256]) -> [u32; 256] {
        let z = zetas();
        let mut cur = *w;
        for layer in 0..8 {
            let len = 128 >> layer;
            let mut nxt = [0u32; 256];
            for b in 0..(1 << layer) {
                let zeta = z[(1 << layer) + b];
                let start = 2 * len * b;
                for j in start..start + len {
                    let t = self.mul(zeta, cur[j + len]);
                    nxt[j] = self.add(cur[j], t);
                    nxt[j + len] = self.sub(cur[j], t);
                }
            }
            cur = nxt;
        }
        cur
    }

    /// FIPS 204 NTT^-1 in the guest's order, then the scaling by 256^-1.
    pub fn intt(&mut self, w: &[u32; 256]) -> [u32; 256] {
        let z = zetas();
        let mut cur = *w;
        for s in 0..8 {
            let len = 1 << s;
            let mut nxt = [0u32; 256];
            for b in 0..(128 >> s) {
                let zeta = z[(256 >> s) - 1 - b];
                let start = 2 * len * b;
                for j in start..start + len {
                    nxt[j] = self.add(cur[j], cur[j + len]);
                    let t = self.sub(cur[j + len], cur[j]);
                    nxt[j + len] = self.mul(zeta, t);
                }
            }
            cur = nxt;
        }
        cur.map(|v| self.mul(FINV, v))
    }
}

/// 256^-1 mod q.
pub const FINV: u32 = 8347681;

#[cfg(test)]
mod tests {
    use super::*;

    fn schoolbook(a: &[u32; 256], b: &[u32; 256]) -> [u32; 256] {
        let mut out = [0i128; 256];
        for i in 0..256 {
            for j in 0..256 {
                let p = a[i] as i128 * b[j] as i128;
                if i + j < 256 {
                    out[i + j] += p;
                } else {
                    out[i + j - 256] -= p;
                }
            }
        }
        out.map(|v| v.rem_euclid(Q as i128) as u32)
    }

    #[test]
    fn ntt_multiplies_negacyclically() {
        let mut h = Hints::default();
        let mut mq = Mq(&mut h);
        let a: [u32; 256] = std::array::from_fn(|i| (i as u32 * 7919 + 13) % Q);
        let b: [u32; 256] = std::array::from_fn(|i| (i as u32 * 104729 + 5) % Q);
        let (fa, fb) = (mq.ntt(&a), mq.ntt(&b));
        let prod: [u32; 256] = std::array::from_fn(|i| mq.mul(fa[i], fb[i]));
        assert_eq!(mq.intt(&prod), schoolbook(&a, &b));
        let fa = mq.ntt(&a);
        assert_eq!(mq.intt(&fa), a);
    }
}
