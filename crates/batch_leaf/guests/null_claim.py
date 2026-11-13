# The empty scheme: each claim is hinted and only the batch rules apply. It isolates the
# batch statement (count, ordering, Keccak) from any signature verification.


def setup_scheme():
    return 0


def verify_claim(ctx):
    c = StackBuf(2)
    hint_witness(c, "claim")
    return c[0], c[1]
