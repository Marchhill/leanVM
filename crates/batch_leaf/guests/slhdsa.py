# SLH-DSA-SHAKE-128s (FIPS 205, pure, empty context) claim:
# claim = Keccak-256(CLAIM_TAG || PK.seed || PK.root || M), M 32 bytes.
#
# n = 16 bytes is one cell, so F and H are one SHA3 instruction each (SHAKE256 of at most
# 80 bytes, padded in the state); T_len, T_k and H_msg run the lane sponge. ADRS is two
# cells, A = (layer, tree) and B = (type, word1, word2, word3), every field big-endian;
# each field is built linearly from bits or from the byte table.

CLAIM_TAG = CLAIM_TAG_PLACEHOLDER
SL_K = 14
SL_A = 12
SL_D = 7
SL_HP = 9
SL_LEN = 35
SL_LEN1 = 32
SL_MAX_CSUM = 480
# byte offsets of the B-cell fields' least significant bytes
SL_TYPE = 3
SL_KP = 7
SL_W2 = 11
SL_W3 = 15
BT_PAIRS = BT_PAIRS_PLACEHOLDER
BT_D0 = BT_D0_PLACEHOLDER
BT_D1 = BT_D1_PLACEHOLDER


def setup_scheme():
    bt = HeapBuf(256)
    load_checked(bt, GEN ** BT_PAIRS, BT_D0, BT_D1)
    return bt


@inline
def shake_f(seed, ad_a, ad_b, m):
    s = StackBuf(13)
    s[0] = seed
    s[1] = ad_a
    s[2] = ad_b
    s[3] = m
    s[4] = SHAKE_PAD
    s[5] = 0
    s[6] = 0
    s[7] = 0
    s[8] = LANE_TOP
    s[9] = 0
    s[10] = 0
    s[11] = 0
    s[12] = 0
    o = StackBuf(2)
    keccak_permute(s, o)
    return o[0]


@inline
def shake_h(seed, ad_a, ad_b, m1, m2):
    s = StackBuf(13)
    s[0] = seed
    s[1] = ad_a
    s[2] = ad_b
    s[3] = m1
    s[4] = m2
    s[5] = SHAKE_PAD
    s[6] = 0
    s[7] = 0
    s[8] = LANE_TOP
    s[9] = 0
    s[10] = 0
    s[11] = 0
    s[12] = 0
    o = StackBuf(2)
    keccak_permute(s, o)
    return o[0]


def shake_t(seed, ad_a, ad_b, cells, lanes, st, n: Const, nb: Const):
    # T_l(seed, ADRS, cells[0..n)) = SHAKE256 of 16 (n + 3) bytes, first 16 output bytes.
    put_cell(seed, lanes)
    put_cell(ad_a, lanes * GEN ** 2)
    put_cell(ad_b, lanes * GEN ** 4)
    for i in mul_range(1, GEN ** n):
        put_cell(cells[i], lanes * GEN ** 6 * i ** 2)
    lanes[GEN ** (2 * n + 6)] = SHAKE_PAD
    for k in unroll(2 * n + 7, 17 * nb - 1):
        lanes[GEN ** k] = 0
    lanes[GEN ** (17 * nb - 1)] = LANE_TOP
    fin = sponge(lanes, nb, 17, st)
    return fin[1]


def chain(x, start_g, b_base, seed, ad_a, bt):
    # F from hash address start up to 14; the hash address is word3's low byte.
    count_g = GEN ** 15 / start_g
    vals = HeapBuf(17)
    vals[1] = x
    for t in mul_range(1, count_g):
        vals[t * GEN] = shake_f(seed, ad_a, b_base + bt[start_g * t] * COORD_BASIS[8 * SL_W3], vals[t])
    return vals[count_g]


def wots_pk(node, ad_a, kp, seed, bt):
    # WOTS+ public key from a signature on node: digits (hinted g-powers) rebuild node and
    # their checksum; each chain finishes from its digit.
    d = HeapBuf(SL_LEN)
    hint_witness(d[0:SL_LEN], "sl_digits")
    acc = 0
    total = 1
    for i in unroll(0, SL_LEN1):
        e = d[GEN ** i]
        assert log(e) < 16
        acc += bt[e] * COORD_BASIS[8 * (i // 2) + 4 * (1 - i % 2)]
        total = total * e
    assert acc == node
    for j in unroll(0, 3):
        e = d[GEN ** (SL_LEN1 + j)]
        assert log(e) < 16
        total = total * e ** (16 ** (2 - j))
    assert total == GEN ** SL_MAX_CSUM
    sig = HeapBuf(SL_LEN)
    hint_witness(sig[0:SL_LEN], "sl_wots")
    tips = HeapBuf(SL_LEN)
    for i in mul_range(1, GEN ** SL_LEN):
        b_base = kp + bt[i] * COORD_BASIS[8 * SL_W2]
        tips[i] = chain(sig[i], d[i], b_base, seed, ad_a, bt)
    tl = HeapBuf(85)
    ts = HeapBuf(78)
    pk = shake_t(seed, ad_a, kp + const(1 * 2 ** (8 * SL_TYPE)), tips, tl, ts, SL_LEN, 5)
    return pk


def verify_claim(ctx):
    bt = ctx
    r = hint_witness("sl_r")
    pk = StackBuf(2)
    hint_witness(pk, "sl_pk")
    seed = pk[0]
    root = pk[1]
    m = StackBuf(2)
    hint_witness(m, "sl_msg")
    claim = StackBuf(2)
    keccak([CLAIM_TAG, seed, root, m[0], m[1]], claim)

    # H_msg = SHAKE256(R || PK.seed || PK.root || 0x00 0x00 || M, 30 bytes); M starts at byte 50.
    ml = HeapBuf(4)
    put_cell(m[0], ml)
    put_cell(m[1], ml * GEN ** 2)
    mb = HeapBuf(32)
    for k in unroll(0, 4):
        lane_bytes(ml[GEN ** k], mb * GEN ** (8 * k), bt)
    hl = HeapBuf(17)
    put_cell(r, hl)
    put_cell(seed, hl * GEN ** 2)
    put_cell(root, hl * GEN ** 4)
    for lane in unroll(6, 11):
        acc = 0
        for p in unroll(0, 32):
            if const((50 + p) // 8 == lane):
                acc = acc + bt[mb[GEN ** p]] * COORD_BASIS[8 * ((50 + p) % 8)]
        if const(lane == 10):
            acc = acc + const(SHAKE_PAD * 2 ** 16)
        hl[GEN ** lane] = acc
    for k in unroll(11, 16):
        hl[GEN ** k] = 0
    hl[GEN ** 16] = LANE_TOP
    hst = HeapBuf(26)
    hfin = sponge(hl, 1, 17, hst)
    dl = HeapBuf(4)
    put_cell(hfin[1], dl)
    put_cell(hfin[GEN], dl * GEN ** 2)
    bits = HeapBuf(256)
    for l in unroll(0, 4):
        lane_bits(dl[GEN ** l], bits * GEN ** (64 * l))

    # idx_tree: bytes 21..27 big-endian mod 2^54; idx_leaf: bytes 28..29 big-endian mod 2^9.
    # tree address of layer j: idx_tree >> 9 j as a 12-byte big-endian field ending at A's byte 15.
    # FORS key pair (and layer 0's): idx_leaf in word1 (B's byte 7).
    kp0 = 0
    for v in unroll(0, SL_HP):
        kp0 += bits[GEN ** (8 * (29 - v // 8) + v % 8)] * COORD_BASIS[8 * (SL_KP - v // 8) + v % 8]
    tree0 = 0
    for v in unroll(0, 54):
        tree0 += bits[GEN ** (8 * (27 - v // 8) + v % 8)] * COORD_BASIS[8 * (15 - v // 8) + v % 8]

    # FORS: tree i's leaf index is md bits 12 i .. 12 i + 11, most significant first.
    roots = HeapBuf(SL_K)
    b_fors = kp0 + const(3 * 2 ** (8 * SL_TYPE))
    for i in unroll(0, SL_K):
        fs = HeapBuf(SL_A + 1)
        hint_witness(fs[0:SL_A + 1], "sl_fors")
        # tree index at height z: (i 2^12 + idx) >> z, two bytes ending at B's byte 15.
        leaf_b = b_fors + const((i * 2 ** SL_A) % 256 * 2 ** (8 * SL_W3) + (i * 2 ** SL_A) // 256 * 2 ** (8 * SL_W3 - 8))
        for v in unroll(0, SL_A):
            leaf_b += bits[GEN ** (8 * ((12 * i + 11 - v) // 8) + 7 - (12 * i + 11 - v) % 8)] * COORD_BASIS[8 * (SL_W3 - v // 8) + v % 8]
        node = shake_f(seed, tree0, leaf_b, fs[1])
        for z in unroll(1, SL_A + 1):
            sib = fs[GEN ** z]
            dbit = bits[GEN ** (8 * ((12 * i + 11 - (z - 1)) // 8) + 7 - (12 * i + 11 - (z - 1)) % 8)]
            t = (i * 2 ** SL_A) // (2 ** z)
            hb = b_fors + const(z * 2 ** (8 * SL_W2) + t % 256 * 2 ** (8 * SL_W3) + t // 256 * 2 ** (8 * SL_W3 - 8))
            for v in unroll(z, SL_A):
                hb += bits[GEN ** (8 * ((12 * i + 11 - v) // 8) + 7 - (12 * i + 11 - v) % 8)] * COORD_BASIS[8 * (SL_W3 - (v - z) // 8) + (v - z) % 8]
            kids = order_children(node, sib, dbit)
            node = shake_h(seed, tree0, hb, kids[0], kids[1])
        roots[GEN ** i] = node
    kl = HeapBuf(51)
    ks = HeapBuf(52)
    signed = shake_t(seed, tree0, kp0 + const(4 * 2 ** (8 * SL_TYPE)), roots, kl, ks, SL_K, 3)

    # Hypertree: layer j signs what layer j - 1 produced.
    for j in unroll(0, SL_D):
        ad_a = const(j * 2 ** (8 * 3))
        for v in unroll(9 * j, 54):
            ad_a += bits[GEN ** (8 * (27 - v // 8) + v % 8)] * COORD_BASIS[8 * (15 - (v - 9 * j) // 8) + (v - 9 * j) % 8]
        kp = 0
        for v in unroll(0, SL_HP):
            if const(j == 0):
                kp += bits[GEN ** (8 * (29 - v // 8) + v % 8)] * COORD_BASIS[8 * (SL_KP - v // 8) + v % 8]
            else:
                kp += bits[GEN ** (8 * (27 - (9 * (j - 1) + v) // 8) + (9 * (j - 1) + v) % 8)] * COORD_BASIS[8 * (SL_KP - v // 8) + v % 8]
        node = wots_pk(signed, ad_a, kp, seed, bt)
        auth = HeapBuf(SL_HP)
        hint_witness(auth[0:SL_HP], "sl_auth")
        for z in unroll(1, SL_HP + 1):
            hb = const(2 * 2 ** (8 * SL_TYPE) + z * 2 ** (8 * SL_W2))
            for v in unroll(z, SL_HP):
                if const(j == 0):
                    hb += bits[GEN ** (8 * (29 - v // 8) + v % 8)] * COORD_BASIS[8 * (SL_W3 - (v - z) // 8) + (v - z) % 8]
                else:
                    hb += bits[GEN ** (8 * (27 - (9 * (j - 1) + v) // 8) + (9 * (j - 1) + v) % 8)] * COORD_BASIS[8 * (SL_W3 - (v - z) // 8) + (v - z) % 8]
            if const(j == 0):
                dbit = bits[GEN ** (8 * (29 - (z - 1) // 8) + (z - 1) % 8)]
            else:
                dbit = bits[GEN ** (8 * (27 - (9 * (j - 1) + z - 1) // 8) + (9 * (j - 1) + z - 1) % 8)]
            kids = order_children(node, auth[GEN ** (z - 1)], dbit)
            node = shake_h(seed, ad_a, hb, kids[0], kids[1])
        signed = node
    assert signed == root
    return claim[0], claim[1]
