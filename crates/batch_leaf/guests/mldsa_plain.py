# ML-DSA-44 (FIPS 204, pure, empty context) claim:
# claim = Keccak-256(CLAIM_TAG || pk || M), pk the 1312-byte encoded key, M 32 bytes.

def verify_claim(ctx):
    aux = ctx[GEN]

    # pk lanes, padded for tr = SHAKE256(pk, 64); M as four lanes.
    pk = HeapBuf(170)
    hint_witness(pk[0:164], "ml_pk")
    for k in mul_range(1, GEN ** 82):
        assert_in_k(pk[k * k], pk[k * k * GEN])
    pk[GEN ** 164] = SHAKE_PAD
    for k in unroll(165, 169):
        pk[GEN ** k] = 0
    pk[GEN ** 169] = LANE_TOP
    msg = StackBuf(4)
    hint_witness(msg, "ml_msg")
    assert_in_k(msg[0], msg[1])
    assert_in_k(msg[2], msg[3])

    # claim = Keccak-256(tag || pk || M): 170 lanes, 11 blocks.
    cl = HeapBuf(187)
    cl[1] = CLAIM_TAG_0
    cl[GEN] = CLAIM_TAG_1
    for k in mul_range(1, GEN ** 164):
        cl[GEN ** 2 * k] = pk[k]
    for k in unroll(0, 4):
        cl[GEN ** (166 + k)] = msg[k]
    cl[GEN ** 170] = 1
    for k in unroll(171, 186):
        cl[GEN ** k] = 0
    cl[GEN ** 186] = LANE_TOP
    cls = HeapBuf(13 * 12)
    claim = sponge(cl, 11, 17, cls)

    # mu = SHAKE256(tr || 0x00 0x00 || M, 64): M sits two bytes into lane 8.
    mu_in = HeapBuf(17)
    mb = HeapBuf(32)
    for k in unroll(0, 4):
        lane_bytes(msg[k], mb * GEN ** (8 * k), aux)
    for lane in unroll(8, 13):
        acc = 0
        for p in unroll(0, 32):
            if const((66 + p) // 8 == lane):
                acc = acc + aux[GEN ** BT_OFF * mb[GEN ** p]] * COORD_BASIS[8 * ((66 + p) % 8)]
        if const(lane == 12):
            acc = acc + const(SHAKE_PAD * 2 ** 16)
        mu_in[GEN ** lane] = acc
    for k in unroll(13, 16):
        mu_in[GEN ** k] = 0
    mu_in[GEN ** 16] = LANE_TOP
    mldsa_core(ctx, pk, mu_in)
    return claim[1], claim[GEN]
