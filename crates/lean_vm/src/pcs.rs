//! Witness commitment: an inner-product PCS committing over `K = F_{2^64}` and
//! opening over `E = F_{2^192}` (doc §sec:stacking, §annex:pcs), reusing flock's **WHIR**. An
//! opening proves `Σ_x q(x)·W(x) = C` against any verifier-evaluable `E`-valued
//! weight `W` (a point evaluation `q̂(r)` is `W = eq(r,·)`). A batch of claims
//! `q̂(point_j) = value_j` folds with random `γ`s into one weight and target,
//! opened in a single WHIR run: the verifier evaluates the weight itself,
//! so it never travels. flock's ring-switched `q_flock` claims join the same batch
//! ([`::pcs::stack_open`]).
//!
//! The stacked witness is `2^μ` words, but its tail past the placed columns is
//! zero, and the L0 interleaving makes that tail whole lanes: lane `l` is the
//! contiguous block `q[l·2^(μ-LOG_BATCH) ..)`, so only
//! [`crate::witness::StackShape::n_lanes`] of them are ever encoded, and the
//! opening's dense weight, its first `LOG_BATCH` rounds and the stack allocation
//! shrink with them. A leaf image is still `2^LOG_BATCH` words, the absent lanes
//! contributing the zeros their codeword would have been, but they LEAD the image:
//! their whole 64-byte blocks are one chaining value every leaf shares, so the
//! committer hashes them once rather than once per leaf, and only the image's tail
//! rides the proof. Both sides derive the lane count from the announced layout.
//!
//! Security: the K configs use rate-1/2 Johnson list decoding with OOD binding
//! and 128-bit round-by-round soundness ([`::pcs::whir::SECURITY_BITS`]).
//! L0's opening claim supplies its binding evaluation; each deeper commitment
//! takes one explicit OOD sample. The base-field
//! commitment only shrinks the level-0 symbols to 8 bytes; every random
//! ingredient is sampled from `E` with the same error terms as before.

use crate::transcript::{ProverState, Receiver, Transmitter, VerifierState};
use primitives::field::F64;

pub use ::pcs::stack_open::{RingSwitchClaim, RingSwitchOpen, RingSwitchVerify, StackClaim as SlotClaim};
use ::pcs::stack_open::{
    open_batch_mixed_whir_stacked, open_batch_mixed_whir_stacked_consuming, verify_opening_batch_mixed_whir_stacked,
};
use ::pcs::whir::ProverConfig;
use ::pcs::whir::{ProverData, commit as whir_commit, config_for_rate};

/// Row-batch lanes `2^LOG_BATCH`: the Merkle leaf width (`2^LOG_BATCH` F64
/// = 512 bytes/leaf) IS WHIR's INITIAL folding factor: the L0 commit is
/// reused, so the two are one knob ([`::pcs::whir::INITIAL_FOLDING_FACTOR`]).
/// Larger ⇒ far fewer Merkle nodes to hash at the cost of fatter query openings.
pub(crate) const LOG_BATCH: usize = ::pcs::whir::INITIAL_FOLDING_FACTOR;
/// The rate the test suite and the benchmarks prove at. Not a default: every
/// entry point takes `log_inv_rate` explicitly, and a caller has to choose.
pub const TEST_LOG_INV_RATE: usize = ::pcs::whir::LOG_INV_RATE_0;
/// The `log_inv_rate` values a WHIR configuration can be derived for.
pub use ::pcs::whir::{MAX_LOG_INV_RATE, MIN_LOG_INV_RATE};
// The PCS and the unground F192 bus argument both target `SECURITY_BITS`.
const _: () = assert!(::pcs::whir::SECURITY_BITS == crate::SECURITY_BITS as usize);
/// Minimum committed-witness log-size accepted by the WHIR level ladder, with one level of margin.
pub const MIN_MU: usize = 15;
/// Largest committed size accepted by all verifiers and compiled into the recursion guest.
pub const MAX_MU: usize = 30;

/// The shared WHIR config for a `2^μ`-word witness, memoized per `(μ, log_inv_rate)`.
fn whir_config(mu: usize, log_inv_rate: usize) -> std::sync::Arc<ProverConfig> {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};
    type Cache = Mutex<HashMap<(usize, usize), Arc<ProverConfig>>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = cache.lock().expect("whir config cache poisoned");
    Arc::clone(map.entry((mu, log_inv_rate)).or_insert_with(|| {
        assert!(
            mu >= MIN_MU,
            "witness must be ≥ 2^{MIN_MU} elements (padded by placements_of)"
        );
        let config = config_for_rate(mu, log_inv_rate)
            .unwrap_or_else(|e| panic!("whir config for mu={mu}, log_inv_rate={log_inv_rate}: {e}"));
        Arc::new(config)
    }))
}

/// A committed `K`-valued witness plus the data needed to open it. The witness
/// itself is not retained (the caller still owns it and passes it back to
/// [`open`]), so committing costs no extra full-trace copy.
pub struct Committed {
    /// Codeword + Merkle tree retained for opening. Public so the single stacked
    /// WHIR opening (which also discharges flock's claim over
    /// this same commitment, §hash_flock) can reuse it.
    pub prover_data: ProverData,
    /// `log2` of the witness length in F64 words.
    pub mu: usize,
    /// L0 inverse-rate logarithm bound into the transcript before this commitment.
    pub log_inv_rate: usize,
    committed_len: usize,
}

impl Committed {
    /// Release the codeword during intervening proof stages, retaining its Merkle tree.
    pub fn release_codeword(&mut self) {
        drop(std::mem::take(&mut self.prover_data.codeword));
    }

    /// Re-encode the same immutable witness before opening, without rebinding its root.
    pub fn rebuild_codeword(&mut self, q: &[F64]) {
        assert!(
            self.prover_data.codeword.is_empty(),
            "release the previous codeword first"
        );
        assert_eq!(q.len(), self.committed_len, "witness must match the committed geometry");
        self.prover_data.codeword = ::pcs::whir::encode_codeword(q, self.mu, LOG_BATCH, self.log_inv_rate);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Whir(::pcs::whir::VerifyError),
}

/// Commit a `K`-valued witness of `2^μ` words (`μ ≥ MIN_MU`, from
/// [`crate::witness::placements_of`]) and bind its root into the transcript,
/// before any challenge is sampled. The verifier reads it with
/// [`read_commitment`].
///
/// `witness` is the stack truncated to the lane blocks that carry data
/// ([`crate::witness::StackShape::committed_len`]); the zero tail past them is
/// neither encoded nor hashed, and the resulting commitment is the same one the
/// full `2^μ` witness would have produced.
pub fn commit(
    ps: &mut ProverState,
    witness: &[F64],
    shape: crate::witness::StackShape,
    log_inv_rate: usize,
) -> Committed {
    let mu = shape.mu;
    assert!(
        mu >= MIN_MU,
        "witness must be ≥ 2^{MIN_MU} elements (padded by placements_of)"
    );
    assert_eq!(
        witness.len(),
        shape.committed_len(),
        "witness must be the committed lanes"
    );
    let (commitment, prover_data) = whir_commit(witness, mu, LOG_BATCH, log_inv_rate);
    ps.add_root(&commitment.root);
    Committed {
        prover_data,
        mu,
        log_inv_rate,
        committed_len: witness.len(),
    }
}

// The batching challenges are just `sample()`d inside the stacked opener: every
// claim they combine is already bound: the values rode the stream
// (`add_scalar`) during the bus / constraint / public-input sub-protocols, the
// points are prior challenges, and the offsets are public (reconstructed
// identically from the announced layout).

/// Verifier counterpart of [`commit`]'s root binding: read the committed root
/// from the stream at the start of verification, before sampling any challenge.
pub fn read_commitment(vs: &mut VerifierState) -> Result<[u8; 32], crate::transcript::Error> {
    vs.next_root()
}

/// Open the committed witness: discharge the `points` (leanVM's bus / constraint /
/// public-input claims, as block-sparse slot evaluations) AND flock's
/// ring-switched validity claims, one region per circuit (`rings`: BLAKE2s, then
/// Keccak), in ONE stacked WHIR.
/// The points become the opener's `point_claims`; the opening's Merkle data
/// rides the transcript's phase list, not the scalar stream. The commitment root
/// was already bound by [`commit`], and the point *values* rode the stream
/// during their sub-protocols, so nothing extra is bound here.
///
/// There is no plain (non-ring-switch) path: the witness ALWAYS carries both
/// `q_flock` sub-blocks (≥ 1 padding instance each, §cpu), so every opening is
/// stacked.
pub fn open(ps: &mut ProverState, c: &Committed, q: &[F64], points: &[SlotClaim], rings: &[RingSwitchOpen]) {
    let lane_block = 1usize << (c.mu - LOG_BATCH);
    assert_eq!(q.len() % lane_block, 0, "witness must be whole committed lanes");
    assert!(q.len() <= 1usize << c.mu, "witness must fit the announced size");
    let cfg = whir_config(c.mu, c.log_inv_rate);
    open_batch_mixed_whir_stacked(ps, c.mu, q, &c.prover_data, &cfg, points, rings)
}

/// Open once and release the commitment buffers immediately after their authenticated rows are captured.
pub fn open_consuming(ps: &mut ProverState, c: Committed, q: &[F64], points: &[SlotClaim], rings: &[RingSwitchOpen]) {
    assert_eq!(q.len(), c.committed_len, "witness must match the committed geometry");
    let cfg = whir_config(c.mu, c.log_inv_rate);
    open_batch_mixed_whir_stacked_consuming(ps, c.mu, q, c.prover_data, &cfg, points, rings)
}

/// Verify the opening (mirror of [`open`]): flock's ring-switched claims
/// and every `points` slot evaluation are checked together in the ONE stacked
/// WHIR against `root`, pulling its Merkle phases off the transcript.
pub fn verify(
    vs: &mut VerifierState,
    points: &[SlotClaim],
    rings: &[RingSwitchVerify<'_>],
    shape: crate::witness::StackShape,
    log_inv_rate: usize,
    root: &[u8; 32],
) -> Result<(), Error> {
    let cfg = whir_config(shape.mu, log_inv_rate);
    verify_opening_batch_mixed_whir_stacked(vs, &cfg, shape.mu, shape.n_lanes, root, points, rings).map_err(Error::Whir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn released_codeword_rebuild_preserves_commitment() {
        let mu = MIN_MU;
        let block = 1 << (mu - LOG_BATCH);
        for rate in [1, 2, 3] {
            for lanes in [1, 3, 37, 64] {
                let q: Vec<_> = (0..block * lanes)
                    .map(|i| F64((i as u64).wrapping_mul(0x9E3779B9)))
                    .collect();
                let (root, prover_data) = whir_commit(&q, mu, LOG_BATCH, rate);
                let expected_codeword = prover_data.codeword.to_vec();
                let expected_tree = prover_data.merkle_tree.to_vec();
                let mut committed = Committed {
                    prover_data,
                    mu,
                    log_inv_rate: rate,
                    committed_len: q.len(),
                };
                committed.release_codeword();
                assert!(committed.prover_data.codeword.is_empty());
                assert_eq!(&*committed.prover_data.merkle_tree, expected_tree);
                committed.rebuild_codeword(&q);
                assert_eq!(&*committed.prover_data.codeword, expected_codeword);
                assert_eq!(&*committed.prover_data.merkle_tree, expected_tree);
                assert_eq!(*committed.prover_data.merkle_tree.last().unwrap(), root.root);
            }
        }
    }

    #[test]
    fn released_codeword_rejects_mismatched_geometry() {
        let mu = MIN_MU;
        let q = vec![F64::ONE; 1 << (mu - LOG_BATCH)];
        let (_, prover_data) = whir_commit(&q, mu, LOG_BATCH, TEST_LOG_INV_RATE);
        let mut committed = Committed {
            prover_data,
            mu,
            log_inv_rate: TEST_LOG_INV_RATE,
            committed_len: q.len(),
        };
        let still_retained = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| committed.rebuild_codeword(&q)));
        assert!(still_retained.is_err());
        committed.release_codeword();
        let wrong_length = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            committed.rebuild_codeword(&q[..q.len() - 1])
        }));
        assert!(wrong_length.is_err());
        assert!(committed.prover_data.codeword.is_empty());
        committed.rebuild_codeword(&q);
    }

    /// What lets all three verifiers check a plain range instead of re-deriving
    /// the ladder: every size in the window is configurable at every rate.
    #[test]
    fn supported_window_is_configurable() {
        for rate in ::pcs::whir::MIN_LOG_INV_RATE..=::pcs::whir::MAX_LOG_INV_RATE {
            for mu in MIN_MU..=MAX_MU {
                assert!(config_for_rate(mu, rate).is_ok(), "mu={mu} rate={rate}");
            }
        }
    }
}
