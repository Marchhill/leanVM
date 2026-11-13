# ML-DSA-44 (FIPS 204 pure ML-DSA, empty context: the COSE -48 / WebAuthn passkey form) over a
# message of any length up to 8 MSG_LANES - 3 bytes.
# claim = Keccak-256(CLAIM_TAG || pk || len(M) as u64 LE || 0x00 0x00 || M), pk the 1312-byte key.
# 0x00 0x00 || M is M' of FIPS 204 Algorithm 3, so the claim and mu absorb the same lanes.

MSG_LANES = 64


def setup_scheme():
    return mldsa_setup()


def verify_claim(ctx):
    aux = ctx[GEN]

    # pk lanes, padded for tr = SHAKE256(pk, 64).
    pk = HeapBuf(170)
    hint_witness(pk[0:164], "ml_pk")
    for k in mul_range(1, GEN ** 82):
        assert_in_k(pk[k * k], pk[k * k * GEN])
    pk[GEN ** 164] = SHAKE_PAD
    for k in unroll(165, 169):
        pk[GEN ** k] = 0
    pk[GEN ** 169] = LANE_TOP

    # M' = 0x00 0x00 || M as nq whole lanes and a partial lane of r < 8 bytes.
    ln = StackBuf(2)
    hint_witness(ln, "ml_mlen")
    nq = ln[0]
    r = ln[1]
    assert log(nq) < MSG_LANES
    assert log(r) < 8
    mw = HeapBuf(MSG_LANES)
    for i in mul_range(1, nq):
        hint_witness(mw[i:i + 1], "ml_mlane")
        assert_in_k(mw[i], 0)
    part = hint_witness("ml_mpart")
    assert_in_k(part, 0)
    pb = HeapBuf(8)
    lane_bytes(part, pb, aux)
    for k in mul_range(1, GEN ** 8 / r):
        assert pb[r * k] == 1
    # M' opens with two zero bytes.
    if nq == 1:
        assert log(r / GEN ** 2) < 6
        assert pb[1] == 1
        assert pb[GEN] == 1
    else:
        fb = HeapBuf(8)
        lane_bytes(mw[1], fb, aux)
        assert fb[1] == 1
        assert fb[GEN] == 1
    # len(M) = 8 nq + r - 2 as a little-endian u64 lane.
    gl = nq ** 8 * r / GEN ** 2
    lb = HeapBuf(32)
    hint_decompose_bits_exponent(lb, gl, 32)
    acc = 1
    lane_len = 0
    for i in unroll(0, 32):
        b = lb[GEN ** i]
        assert b * b == b
        acc = acc * (1 + b * (GEN ** (2 ** i) + 1))
        lane_len = lane_len + b * COORD_BASIS[i]
    assert acc == gl

    # claim: tag(2) pk(164) len(1) then M'.
    cl = HeapBuf(167 + MSG_LANES + 17)
    cl[1] = CLAIM_TAG_0
    cl[GEN] = CLAIM_TAG_1
    for k in mul_range(1, GEN ** 164):
        cl[GEN ** 2 * k] = pk[k]
    cl[GEN ** 166] = lane_len
    cm = cl * GEN ** 167
    for i in mul_range(1, nq):
        cm[i] = mw[i]
    cls = HeapBuf(13 * 16)
    claim = sponge_var(cl, GEN ** 167 * nq, part + r ** 8, cls)

    # mu = SHAKE256(tr || M', 64).
    trst = HeapBuf(13 * 11)
    trs = sponge(pk, 10, 17, trst)
    mu_in = HeapBuf(8 + MSG_LANES + 17)
    state_lanes(trs, mu_in, 4, 0)
    mm = mu_in * GEN ** 8
    for i in mul_range(1, nq):
        mm[i] = mw[i]
    must = HeapBuf(13 * 6)
    mus = sponge_var(mu_in, GEN ** 8 * nq, part + SHAKE_PAD * r ** 8, must)
    mldsa_core(ctx, pk, mus)
    return claim[1], claim[GEN]
