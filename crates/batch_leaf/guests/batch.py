# EIP-8288 batch leaf: N >= 1 claims under one program, published as
# get_batch_hash(claims) = Keccak-256(b'EIP8288:batch:v1' || claim_0 || ... || claim_{N-1})
# in the two 128-bit public-input cells. The claims are produced by the scheme's
# `verify_claim`, one call per claim, and must be strictly increasing as 32-byte strings.
# N is a hint, so one program (one verification key) serves every batch size.

TAG_0 = TAG_0_PLACEHOLDER
TAG_1 = TAG_1_PLACEHOLDER
MAX_CLAIMS = MAX_CLAIMS_PLACEHOLDER
MAX_FULL_BLOCKS = MAX_FULL_BLOCKS_PLACEHOLDER
RATE_LANES = 17
LANE_TOP = 9223372036854775808  # 2^63: the 0x80 closing a Keccak block
Y_INV = Y_INV_PLACEHOLDER
COORD_BASIS = COORD_BASIS_PLACEHOLDER
BASE_FIELD_BITS = 64


def put_cell(x, dst):
    # A canonical 128-bit cell as its two 64-bit lanes, low lane first.
    lo = StackBuf(1)
    hint_f192_limbs(lo, x)
    hi = (x + lo[0]) * Y_INV
    assert_in_k(lo[0], hi)
    dst[1] = lo[0]
    dst[GEN] = hi
    return


def lane_less(a, b):
    # a < b for two lanes compared as the 8 bytes they hold (byte 0 first, each
    # byte's bit 7 first), i.e. as big-endian strings.
    ab = StackBuf(BASE_FIELD_BITS)
    bb = StackBuf(BASE_FIELD_BITS)
    hint_decompose_bits(ab, a, BASE_FIELD_BITS)
    hint_decompose_bits(bb, b, BASE_FIELD_BITS)
    ra = 0
    rb = 0
    eq = 1
    lt = 0
    for byte in unroll(0, 8):
        for bit in unroll(0, 8):
            p = 8 * byte + 7 - bit
            x = ab[p]
            ab[p] = x * x
            y = bb[p]
            bb[p] = y * y
            ra += x * COORD_BASIS[p]
            rb += y * COORD_BASIS[p]
            d = x + y
            lt += eq * d * y
            eq = eq * (1 + d)
    assert ra == a
    assert rb == b
    assert lt == 1
    return


def pick_lanes(prev, cur, k: Const):
    for m in unroll(0, k):
        assert prev[GEN ** m] == cur[GEN ** m]
    return prev[GEN ** k], cur[GEN ** k]


def check_increasing(prev, cur):
    # The first lane where the two claims differ is hinted; the lanes before it
    # must be equal and that lane must order them.
    j = hint_witness("diff_lane")
    assert log(j) < 4
    a, b = match(log(j), range(0, 4), lambda k: pick_lanes(prev, cur, k))
    lane_less(a, b)
    return


def main():
    n = hint_witness("n_claims")
    assert log(n) < MAX_CLAIMS + 1
    assert n != 1
    # Message lanes M = 2 + 4N; M = 17 * full + tail with tail < 17, so the padded
    # message is full + 1 blocks.
    split = StackBuf(2)
    hint_witness(split, "sponge_split")
    full_g = split[0]
    tail_g = split[1]
    assert log(full_g) < MAX_FULL_BLOCKS
    assert log(tail_g) < RATE_LANES
    length_g = n ** 4 * GEN ** 2
    assert full_g ** RATE_LANES * tail_g == length_g
    blocks_g = full_g * GEN
    lanes = HeapBuf(blocks_g ** RATE_LANES)
    lanes[1] = TAG_0
    lanes[GEN] = TAG_1
    body = lanes * GEN ** 2
    for i in mul_range(1, n):
        c0, c1 = verify_claim()
        dst = body * i ** 4
        put_cell(c0, dst)
        put_cell(c1, dst * GEN ** 2)
    for i in mul_range(GEN, n):
        cur = body * i ** 4
        prev = cur / GEN ** 4
        check_increasing(prev, cur)
    # pad10*1 with Keccak's 0x01: lane M gets 0x01, the block's last lane 0x80.
    last_g = blocks_g ** RATE_LANES / GEN
    if length_g == last_g:
        lanes[length_g] = LANE_TOP + 1
    else:
        lanes[length_g] = 1
        zero_0 = length_g * GEN
        zero_1 = last_g / zero_0
        for pos in mul_range(1, zero_1):
            lanes[zero_0 * pos] = 0
        lanes[last_g] = LANE_TOP
    states = HeapBuf((blocks_g * GEN) ** 13)
    for k in unroll(0, 13):
        states[GEN ** k] = 0
    for block in mul_range(1, blocks_g):
        inp = lanes * block ** RATE_LANES
        st = states * block ** 13
        absorbed = StackBuf(13)
        for k in unroll(0, 8):
            absorbed[k] = st[GEN ** k] + inp[GEN ** (2 * k)] + f192(0, 1, 0) * inp[GEN ** (2 * k + 1)]
        absorbed[8] = st[GEN ** 8] + inp[GEN ** 16]
        for k in unroll(9, 13):
            absorbed[k] = st[GEN ** k]
        keccak_permute(absorbed, (states * (block * GEN) ** 13)[0:13])
    final = states * blocks_g ** 13
    p = GEN ** 0
    p[1] = final[1]
    p[GEN] = final[GEN]
    return
