# leanXMSS (BLAKE2s, the prover's native hash) claim:
# claim = Keccak-256(CLAIM_TAG || root || pp || message || epoch), 96 bytes,
# each value one 16-byte cell. The verifier body is the aggregation guest's.

CLAIM_TAG = CLAIM_TAG_PLACEHOLDER


def verify_claim():
    pk = HeapBuf(2)
    hint_witness(pk[0:2], "pk")
    message = HeapBuf(2)
    hint_witness(message[0:2], "msg")
    epoch = hint_witness("epoch")
    merkle_bits = HeapBuf(MERKLE_BIT_CELLS)
    tweak_table = HeapBuf(N_TWEAK_CELLS)
    fill_xmss_epoch_tables(epoch, merkle_bits, tweak_table)
    verify_sig(message, tweak_table, merkle_bits, pk)
    claim = StackBuf(2)
    keccak([CLAIM_TAG, pk[1], pk[GEN], message[1], message[GEN], epoch], claim)
    return claim[0], claim[1]
