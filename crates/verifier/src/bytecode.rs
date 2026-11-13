//! The program a proof is about, prepared once so that verifying many proofs of it hashes its table once.

use crate::field::{E, ZERO, reduce};
use crate::hash::{Digest, keccak_hash};
use crate::layout::{BUS_BITS, COMMITTED_OOD_TAG, COMMITTED_TAG, TAG};
use crate::multilinear::eq_kernel;
use crate::transcript::Sponge;
use crate::{VerifierError, require};

/// The stacked bytecode multilinear, prepared to be evaluated, and the Fiat-Shamir IV it gives every transcript.
///
/// The table is fixed while the points vary, so its words are sorted once: per block of `2^BLOCK_LOG` words, the
/// positions of each distinct nonzero word, and the bytes those words have.
#[derive(Clone, Debug)]
pub struct Bytecode {
    len: usize,
    pub(crate) fiat_shamir_iv: Digest,
    blocks: Vec<Block>,
    /// A distinct word of a block, and where its positions end.
    words: Vec<(u64, usize)>,
    positions: Vec<u16>,
    /// A byte some word of a block has: which of the word's eight, times 256, plus its value.
    bytes: Vec<u16>,
    /// The table's commitment ([`Bytecode::committed`]), when the verifier holds that instead of the table.
    commitment: Option<Commitment>,
}

/// A committed table's root, and the out-of-domain evaluation its key fixes.
#[derive(Clone, Debug)]
struct Commitment {
    root: Digest,
    ood_point: Vec<E>,
    ood_value: E,
}

/// A block with a nonzero word: its index, and where its words and bytes end.
#[derive(Clone, Copy, Debug)]
struct Block {
    index: usize,
    words_end: usize,
    bytes_end: usize,
}

/// How many low coordinates one block of [`Bytecode::evaluate`] spans: their eq table stays in cache, and a block is long enough to amortize closing it.
const BLOCK_LOG: usize = 14;

/// The nonzero bytes of `word`, each as its bucket: which byte, times 256, plus its value.
fn byte_buckets(word: u64) -> impl Iterator<Item = u16> {
    let bytes = word.to_le_bytes().into_iter().enumerate();
    bytes
        .filter(|&(_, value)| value != 0)
        .map(|(byte, value)| 256 * byte as u16 + value as u16)
}

impl Bytecode {
    pub fn new(table: &[u64]) -> Self {
        let fiat_shamir_iv = {
            let iv_preimage: Vec<u8> = TAG
                .iter()
                .copied()
                .chain(table.iter().flat_map(|word| word.to_le_bytes()))
                .collect();
            keccak_hash(&iv_preimage)
        };

        let (mut blocks, mut words, mut positions, mut bytes) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for (index, block) in table.chunks(1 << BLOCK_LOG).enumerate() {
            let mut members = std::collections::BTreeMap::<u64, Vec<u16>>::new();
            for (position, &word) in block.iter().enumerate().filter(|&(_, &word)| word != 0) {
                members.entry(word).or_default().push(position as u16);
            }
            if members.is_empty() {
                continue;
            }
            // Fewest positions first: the sum over a word's positions then runs one length many times over,
            // so its loop exit is predicted.
            let mut members: Vec<(u64, Vec<u16>)> = members.into_iter().collect();
            members.sort_by_key(|(_, at)| at.len());
            let mut used = std::collections::BTreeSet::new();
            for (word, at) in members {
                positions.extend(at);
                words.push((word, positions.len()));
                used.extend(byte_buckets(word));
            }
            bytes.extend(used);
            blocks.push(Block {
                index,
                words_end: words.len(),
                bytes_end: bytes.len(),
            });
        }
        Self {
            len: table.len(),
            fiat_shamir_iv,
            blocks,
            words,
            positions,
            bytes,
            commitment: None,
        }
    }

    /// A program the verifier knows only by `2^log_instructions`, the root of its stacked table's commitment, and
    /// the table's value `ood` ([`committed_ood_encoding`]) at the root's out-of-domain point.
    ///
    /// The Fiat-Shamir IV is [`committed_key`]`(log_instructions, root, ood)`. A proof of such a program sends the
    /// table's value at the bus's point and opens the commitment there and at the out-of-domain point, so verifying
    /// it never touches the table.
    pub fn committed(log_instructions: usize, root: [u8; 32], ood: [u8; 32]) -> Result<Self, VerifierError> {
        require(
            log_instructions + BUS_BITS <= crate::layout::MAX_COMMITTED_BYTECODE_LOG,
            VerifierError::MultilinearSize,
        )?;
        Ok(Self {
            len: 1 << (log_instructions + BUS_BITS),
            fiat_shamir_iv: Digest(committed_key(log_instructions, &root, &ood)),
            blocks: Vec::new(),
            words: Vec::new(),
            positions: Vec::new(),
            bytes: Vec::new(),
            commitment: Some(Commitment {
                root: Digest(root),
                ood_point: committed_ood_point(log_instructions, &root),
                ood_value: committed_ood_value(&ood),
            }),
        })
    }

    /// A malicious prover's switch: walk a transcript under `iv` rather than the program's own IV.
    #[cfg(feature = "forge")]
    #[doc(hidden)]
    pub fn forge_fiat_shamir_iv(mut self, iv: [u8; 32]) -> Self {
        self.fiat_shamir_iv = Digest(iv);
        self
    }

    /// The root of the table's commitment, for a [`Bytecode::committed`] program.
    pub fn commitment(&self) -> Option<[u8; 32]> {
        self.commitment.as_ref().map(|c| c.root.0)
    }

    /// The out-of-domain point and value a [`Bytecode::committed`] program's key fixes.
    pub(crate) fn ood_claim(&self) -> Option<(Vec<E>, E)> {
        self.commitment.as_ref().map(|c| (c.ood_point.clone(), c.ood_value))
    }

    /// The Fiat-Shamir IV every proof of this program is made under.
    pub fn fiat_shamir_iv(&self) -> [u8; 32] {
        self.fiat_shamir_iv.0
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The table's multilinear extension at an LSB-first `point`, equal to `multilinear_eval` of its words.
    ///
    /// The low coordinates' eq table weighs the words of every block, and the high coordinates' weighs the blocks.
    /// Within a block, the weights of each distinct word are summed once and credited to the buckets of its bytes,
    /// and each bucket to every bit its byte value sets: then bit `k` of the words holds its sum, which `x^k` scales.
    pub fn evaluate(&self, point: &[E]) -> Result<E, VerifierError> {
        require(
            self.commitment.is_none() && point.len() < 64 && self.len == 1 << point.len(),
            VerifierError::MultilinearSize,
        )?;
        let (low, high) = point.split_at(point.len().min(BLOCK_LOG));
        let (low_weights, high_weights) = (eq_kernel(low), eq_kernel(high));
        let mut buckets = vec![ZERO; 8 * 256];
        let (mut words_start, mut positions_start, mut bytes_start) = (0, 0, 0);
        let mut total = ZERO;
        for block in &self.blocks {
            for &(word, positions_end) in &self.words[words_start..block.words_end] {
                let members = &self.positions[positions_start..positions_end];
                let sum = E::sum(members.iter().map(|&position| low_weights[position as usize]));
                // Every byte, the zero ones into buckets no block reads, so the loop has no branch on the data.
                for (byte, value) in word.to_le_bytes().into_iter().enumerate() {
                    buckets[256 * byte + value as usize] += sum;
                }
                positions_start = positions_end;
            }
            let mut bit_sums = [ZERO; 64];
            for &bucket in &self.bytes[bytes_start..block.bytes_end] {
                let sum = std::mem::take(&mut buckets[bucket as usize]);
                let (byte, value) = (bucket as usize / 256, bucket as u64 % 256);
                for (bit, bit_sum) in bit_sums[8 * byte..8 * byte + 8].iter_mut().enumerate() {
                    *bit_sum += sum.masked(0u64.wrapping_sub(value >> bit & 1));
                }
            }
            (words_start, bytes_start) = (block.words_end, block.bytes_end);
            total += high_weights[block.index] * monomial_sum(&bit_sums);
        }
        Ok(total)
    }
}

/// The key, and Fiat-Shamir IV, of a program of `2^log_instructions` instructions whose stacked table commits to
/// `root` and takes the value `ood` encodes at [`committed_ood_point`] ([`Bytecode::committed`]): Keccak-256 of
/// [`COMMITTED_TAG`], the log as one byte, the root, then `ood`.
///
/// The tag differs from [`TAG`] in its first bytes, so no key is a table digest's preimage prefix and the two
/// kinds of IV never share a transcript.
pub fn committed_key(log_instructions: usize, root: &[u8; 32], ood: &[u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(COMMITTED_TAG.len() + 1 + 64);
    preimage.extend_from_slice(COMMITTED_TAG);
    preimage.push(log_instructions as u8);
    preimage.extend_from_slice(root);
    preimage.extend_from_slice(ood);
    keccak_hash(&preimage).0
}

/// The out-of-domain point of a committed table: one coordinate per stack variable, each a challenge of the sponge
/// seeded with `root` as the IV and [`COMMITTED_OOD_TAG`] then the log of the instructions as the public input.
///
/// WHIR's first level opens the root in the list-decoding regime, and a root the verifier does not derive itself may
/// sit near several codewords. Fixing the table's value at this point in the key leaves one of them: two distinct
/// stacks of `μ` variables agree there with probability at most `μ/|E|`, so over the Johnson list of `L` codewords at
/// most `L²·μ/(2|E|)` (one sample: `188 - (2 log L - 1)` bits, with `log L ≈ 9.3` at this rate and size).
pub fn committed_ood_point(log_instructions: usize, root: &[u8; 32]) -> Vec<E> {
    let mut public_input = [0u8; 32];
    public_input[..15].copy_from_slice(COMMITTED_OOD_TAG);
    public_input[15] = log_instructions as u8;
    let mut sponge = Sponge::new(Digest(*root), Digest(public_input));
    let stack_log = crate::committed_bytecode_stack_log(1 << (log_instructions + BUS_BITS));
    (0..stack_log).map(|_| sponge.sample()).collect()
}

/// A value as the two 16-byte cells a committed key carries it in: `c0 ‖ c1`, then `c2` and eight zero bytes.
pub fn committed_ood_encoding(value: E) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, limb) in out
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .zip([value.c0, value.c1, value.c2])
    {
        *chunk = limb.to_le_bytes();
    }
    out
}

/// The value two cells `a ‖ b` encode, `a + y²·b`: any such pair is admitted, as the guest admits it.
fn committed_ood_value(ood: &[u8; 32]) -> E {
    let limb = |i: usize| u64::from_le_bytes(ood.as_chunks::<8>().0[i]);
    let (a, b) = (E::new(limb(0), limb(1), 0), E::new(limb(2), limb(3), 0));
    a + E::new(0, 0, 1) * b
}

/// `sum_k x^k * sums[k]`: each limb shifted into place, then one reduction.
fn monomial_sum(sums: &[E; 64]) -> E {
    let (mut c0, mut c1, mut c2) = (0u128, 0u128, 0u128);
    for (k, sum) in sums.iter().enumerate() {
        c0 ^= (sum.c0 as u128) << k;
        c1 ^= (sum.c1 as u128) << k;
        c2 ^= (sum.c2 as u128) << k;
    }
    E::new(reduce(c0), reduce(c1), reduce(c2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::K;
    use crate::multilinear::multilinear_eval;

    #[test]
    fn evaluate_matches_the_fold() {
        // An xorshift stream: words with every byte live, short words, a run of zeros, a zero block, and points on both sides of the block split.
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for variables in [0, 3, BLOCK_LOG, BLOCK_LOG + 2] {
            let mut table: Vec<u64> = (0..1 << variables).map(|_| next()).collect();
            for word in table.iter_mut().skip(5).take(40) {
                *word = 0;
            }
            for word in table.iter_mut().skip(50).step_by(3) {
                *word >>= 40;
            }
            for word in table.iter_mut().skip(2 << BLOCK_LOG).take(1 << BLOCK_LOG) {
                *word = 0;
            }
            let point: Vec<E> = (0..variables).map(|_| E::new(next(), next(), next())).collect();
            let words: Vec<K> = table.iter().map(|&word| K(word)).collect();
            let bytecode = Bytecode::new(&table);
            assert_eq!(bytecode.evaluate(&point), multilinear_eval(&words, &point));
        }
    }
}
