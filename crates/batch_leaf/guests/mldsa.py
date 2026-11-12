# ML-DSA-44 (FIPS 204, pure, empty context) claim:
# claim = Keccak-256(CLAIM_TAG || pk || M), pk the 1312-byte encoded key, M 32 bytes.
#
# The signature is a witness and only its acceptance is proven: c~ is recomputed from
# mu and w1 and compared; z and the hint vector h are taken as coefficients (not their
# byte encoding), with ||z||_inf < gamma1 - beta and |h| <= omega checked.

CLAIM_TAG_0 = CLAIM_TAG_0_PLACEHOLDER
CLAIM_TAG_1 = CLAIM_TAG_1_PLACEHOLDER
ML_TAU = 39
GAMMA2 = 95232
# aux table layout
BT_OFF = 0
S16_OFF = 256
S256_OFF = 384
TG_OFF = 400
NZ_OFF = 489
CR0_OFF = 492
CR1_OFF = 495
CRF_OFF = 498
W_OFF = 501
W_LEN = 356
AUX_SIZE = 2281
CRV = CRV_PLACEHOLDER
ZT_PAIRS = ZT_PAIRS_PLACEHOLDER
ZT_D0 = ZT_D0_PLACEHOLDER
ZT_D1 = ZT_D1_PLACEHOLDER
BT_PAIRS = BT_PAIRS_PLACEHOLDER
BT_D0 = BT_D0_PLACEHOLDER
BT_D1 = BT_D1_PLACEHOLDER
WT_PAIRS = WT_PAIRS_PLACEHOLDER
WT_D0 = WT_D0_PLACEHOLDER
WT_D1 = WT_D1_PLACEHOLDER


def setup_scheme():
    tb = build_tables()
    zt = HeapBuf(POLY_CELLS)
    load_checked(zt, GEN ** ZT_PAIRS, ZT_D0, ZT_D1)
    finv = HeapBuf(REC)
    for k in unroll(0, REC):
        finv[GEN ** k] = FINV_REC[k]
    aux = HeapBuf(AUX_SIZE)
    load_checked(aux * GEN ** BT_OFF, GEN ** BT_PAIRS, BT_D0, BT_D1)
    aux[GEN ** S16_OFF] = 1
    for v in mul_range(1, GEN ** 127):
        aux[GEN ** (S16_OFF + 1) * v] = aux[GEN ** S16_OFF * v] * GEN ** 16
    aux[GEN ** S256_OFF] = 1
    for v in mul_range(1, GEN ** 15):
        aux[GEN ** (S256_OFF + 1) * v] = aux[GEN ** S256_OFF * v] * GEN ** 256
    aux[GEN ** TG_OFF] = 1
    for v in mul_range(1, GEN ** 88):
        aux[GEN ** (TG_OFF + 1) * v] = aux[GEN ** TG_OFF * v] * GEN ** GAMMA2
    aux[GEN ** NZ_OFF] = 1
    aux[GEN ** (NZ_OFF + 1)] = GEN
    aux[GEN ** (NZ_OFF + 2)] = GEN
    for v in unroll(0, 9):
        aux[GEN ** (CR0_OFF + v)] = CRV[v]
    load_checked(aux * GEN ** W_OFF, GEN ** WT_PAIRS, WT_D0, WT_D1)
    ctx = HeapBuf(4)
    ctx[1] = tb
    ctx[GEN] = aux
    ctx[GEN ** 2] = zt
    ctx[GEN ** 3] = finv
    return ctx


# ------------------------------------------------------------------ ExpandA


def rej_cand(b3, ci, nc, out, aux, tb):
    # One RejNTTPoly candidate b0 + 256 b1 + 65536 (b2 mod 128), accepted iff < q.
    b0 = b3[1]
    sp = StackBuf(4)
    hint_witness(sp, "rej_split")
    assert log(sp[0]) < 16
    assert log(sp[1]) < 16
    assert log(sp[2]) < 128
    sp[3] = sp[3] * sp[3]
    assert b3[GEN] == sp[0] * aux[GEN ** S16_OFF * sp[1]]
    assert b3[GEN ** 2] == sp[2] * (1 + sp[3] * (GEN ** 128 + 1))
    r0 = b0 * aux[GEN ** S256_OFF * sp[0]]
    r1 = sp[1] * aux[GEN ** S16_OFF * sp[2]]
    gr = r0 * tb[GEN ** P1_OFF * r1]
    acc = hint_witness("rej_acc")
    if acc == 1:
        wy = hint_witness("rej_wy")
        assert log(r1) < R1_BOUND
        assert (r0 + 1) * (1 + (r1 + GEN ** 2046) * wy) == 0
        rec = out * ci ** REC
        rec[1] = r0
        rec[GEN] = r1
        rec[GEN ** 2] = gr
        nc[1] = ci * GEN
    else:
        assert log(r1 / GEN ** 2046) < 2
        assert gr != GEN ** (Q_MOD - 1)
        nc[1] = ci
    return


def rej_ntt_poly(pk, lane4, out, aux, tb):
    lanes = HeapBuf(21)
    for k in unroll(0, 4):
        lanes[GEN ** k] = pk[GEN ** k]
    lanes[GEN ** 4] = lane4
    for k in unroll(5, 20):
        lanes[GEN ** k] = 0
    lanes[GEN ** 20] = LANE_TOP
    nb = hint_witness("rej_nb")
    assert log(nb) < 9
    st = HeapBuf(13 * 10)
    for k in unroll(0, 13):
        st[GEN ** k] = 0
    absorb_block(st, lanes, st * GEN ** 13, 21)
    for b in mul_range(GEN, nb):
        nxt = StackBuf(13)
        cur = st * b ** 13
        for k in unroll(0, 13):
            nxt[k] = cur[GEN ** k]
        keccak_permute(nxt, (st * (b * GEN) ** 13)[0:13])
    by = HeapBuf(168 * 8)
    for b in mul_range(1, nb):
        sl = HeapBuf(21)
        state_lanes(st * (b * GEN) ** 13, sl, 8, 5)
        bb = by * b ** 168
        for l in mul_range(1, GEN ** 21):
            lane_bytes(sl[l], bb * l ** 8, aux)
    ncand = hint_witness("rej_n")
    assert log(ncand) < log(nb ** 56)
    cur = HeapBuf(449)
    cur[1] = 1
    for c in mul_range(1, ncand):
        rej_cand(by * c ** 3, cur[c], cur * c * GEN, out, aux, tb)
    assert cur[ncand] == GEN ** 256
    return


# ------------------------------------------------------------------ SampleInBall


def sib_move(prev, now, n_g, hit, j, gi):
    # Entries e < t: the one at position j (if hit names it) moves to i.
    for e in mul_range(1, n_g):
        p_old = prev[e]
        if e == hit:
            assert p_old == j
            now[e] = gi
        else:
            assert p_old != j
            now[e] = p_old
    return


def sample_in_ball(sb, signs, aux, crec):
    # FIPS 204 SampleInBall over the stream bytes sb (after the 8 sign bytes), kept as
    # a list of (position, sign) entries: step t appends (j_t, s_t), and the entry
    # already at j_t, if any, moves to i = 256 - tau + t.
    pos = HeapBuf(40 * ML_TAU)
    cur = HeapBuf(ML_TAU + 1)
    cur[1] = 1
    # Bounds that vary with t are runtime values (all at most 256, under the 2^16 cap).
    one = cur[1]
    for t in unroll(0, ML_TAU):
        skip = hint_witness("sib_skip")
        assert log(skip) < 128
        c0 = cur[GEN ** t]
        if const(t + 1 != ML_TAU):
            for k in mul_range(1, skip):
                assert log(sb[c0 * k] / GEN ** (217 + t + 1)) < log(GEN ** (256 - (217 + t + 1)) * one)
        else:
            assert skip == 1
        j = sb[c0 * skip]
        assert log(j) < log(GEN ** (217 + t + 1) * one)
        cur[GEN ** (t + 1)] = c0 * skip * GEN
        hit = hint_witness("sib_hit")
        assert log(hit) < log(GEN ** (t + 1) * one)
        now = pos * GEN ** (40 * t)
        if const(t != 0):
            sib_move(pos * GEN ** (40 * (t - 1)), now, GEN ** t, hit, j, GEN ** (217 + t))
        now[GEN ** t] = j
    assert log(cur[GEN ** ML_TAU]) < 129
    cc = HeapBuf(256)
    hint_witness(cc[0:256], "sib_codes")
    cnt = HeapBuf(257)
    cnt[1] = 1
    for k in mul_range(1, GEN ** 256):
        code = cc[k]
        assert log(code) < 3
        cnt[k * GEN] = cnt[k] * aux[GEN ** NZ_OFF * code]
        rec = crec * k ** REC
        rec[1] = aux[GEN ** CR0_OFF * code]
        rec[GEN] = aux[GEN ** CR1_OFF * code]
        rec[GEN ** 2] = aux[GEN ** CRF_OFF * code]
    assert cnt[GEN ** 256] == GEN ** ML_TAU
    last = pos * GEN ** (40 * (ML_TAU - 1))
    for e in mul_range(1, GEN ** ML_TAU):
        assert cc[last[e]] == GEN * (1 + signs[e] * (GEN + 1))
    return


# ------------------------------------------------------------------ signature vectors


def load_z(rec, tb):
    # |z| = m < gamma1 - beta with sign sg; rec = z mod q.
    hz = StackBuf(5)
    hint_witness(hz, "ml_z")
    hz[1] = hz[1] * hz[1]
    hz[2] = hz[2] * hz[2]
    assert log(hz[0] * (1 + hz[1] * (GEN ** 78 + 1))) < 65536
    gm = hz[0] * (1 + hz[1] * (GEN ** 65536 + 1))
    assert log(hz[3]) < LIMB
    assert log(hz[4]) < R1_BOUND
    v = hz[3] * tb[GEN ** P1_OFF * hz[4]]
    assert v == gm + hz[2] * (GEN ** Q_MOD / gm + gm)
    rec[1] = hz[3]
    rec[GEN] = hz[4]
    rec[GEN ** 2] = v
    return


def t1_rec(bits, rec, tb):
    # t1 2^13 from ten bits: limbs (0, 2 t1).
    acc = 1
    for b in unroll(0, 10):
        acc = acc * (1 + bits[GEN ** b] * (GEN ** (2 ** b) + 1))
    hi = acc * acc
    rec[1] = 1
    rec[GEN] = hi
    rec[GEN ** 2] = tb[GEN ** P1_OFF * hi]
    return


def use_hint_idx(w, hbit, aux):
    # Decompose(w) as w = t gamma2 + s, s < gamma2: UseHint depends only on t, [s = 0]
    # and h, so the result is looked up at index 4 t + 2 [s = 0] + h.
    hs = StackBuf(6)
    hint_witness(hs, "uh")
    tq = hs[0]
    slo = hs[1]
    hs[2] = hs[2] * hs[2]
    zb = hs[3]
    assert log(tq) < 89
    assert log(slo * (1 + hs[2] * (GEN ** 35840 + 1))) < 65536
    gs = slo * (1 + hs[2] * (GEN ** 65536 + 1))
    dd = w[GEN ** 2] / (aux[GEN ** TG_OFF * tq] * gs)
    assert (dd + 1) * (dd + GEN ** Q_MOD) == 0
    x = gs + 1
    assert zb * x == 0
    assert zb + x * hs[4] == 1
    assert (1 + zb) * (1 + (tq + GEN ** 88) * hs[5]) == 0
    return tq ** 4 * (1 + zb * (GEN ** 2 + 1)) * (1 + hbit * (GEN + 1))


def row_coeff(arow, zp, ch, th, acc, k, tb):
    # (A z - c t1 2^d)[k] for one row, plus q 2^24 to keep the exponent positive.
    p = GEN ** (Q_MOD * H2)
    for i in unroll(0, 4):
        a = arow * GEN ** (POLY_CELLS * i) * k ** REC
        zz = zp[GEN ** i] * k ** REC
        p = p * mq_prod(a[1], a[GEN], zz[1], zz[GEN], tb)
    cc = ch * k ** REC
    tt = th * k ** REC
    p = p / mq_prod(cc[1], cc[GEN], tt[1], tt[GEN], tb)
    r = mq_red_wide(p, tb)
    # NTT^-1's first layer reads only g^r.
    (acc * k ** REC)[GEN ** 2] = r[2]
    return


def encode_group(grp, wv, hh, hin, aux):
    # 32 coefficients of w1 (6 bits each) into three lanes of the c~' input.
    base = grp ** 32
    l0 = 0
    l1 = 0
    l2 = 0
    for m in unroll(0, 32):
        k = base * GEN ** m
        idx = use_hint_idx(wv * k ** REC, hh[k], aux)
        if const(m == 10):
            l0 = l0 + aux[GEN ** (W_OFF + W_LEN) * idx] * COORD_BASIS[60]
            l1 = l1 + aux[GEN ** (W_OFF + 2 * W_LEN) * idx]
        elif const(m == 21):
            l1 = l1 + aux[GEN ** (W_OFF + 3 * W_LEN) * idx] * COORD_BASIS[62]
            l2 = l2 + aux[GEN ** (W_OFF + 4 * W_LEN) * idx]
        elif const(6 * m // 64 == 0):
            l0 = l0 + aux[GEN ** W_OFF * idx] * COORD_BASIS[6 * m]
        elif const(6 * m // 64 == 1):
            l1 = l1 + aux[GEN ** W_OFF * idx] * COORD_BASIS[6 * m - 64]
        else:
            l2 = l2 + aux[GEN ** W_OFF * idx] * COORD_BASIS[6 * m - 128]
    dst = hin * GEN ** 8 * grp ** 3
    dst[1] = l0
    dst[GEN] = l1
    dst[GEN ** 2] = l2
    return


# ------------------------------------------------------------------ verification


def mldsa_core(ctx, pk, mu_in):
    # ML-DSA-44 verification of the message whose lanes 8..16 of mu's input the caller
    # wrote (M' after tr, padded); pk is the hinted, padded key buffer.
    tb = ctx[1]
    aux = ctx[GEN]
    zt = ctx[GEN ** 2]
    finv = ctx[GEN ** 3]
    trst = HeapBuf(13 * 11)
    trs = sponge(pk, 10, 17, trst)
    state_lanes(trs, mu_in, 4, 0)
    must = HeapBuf(26)
    mus = sponge(mu_in, 1, 17, must)

    # c = SampleInBall(c~).
    ct = StackBuf(4)
    hint_witness(ct, "ml_ctilde")
    assert_in_k(ct[0], ct[1])
    assert_in_k(ct[2], ct[3])
    sib_in = HeapBuf(17)
    for k in unroll(0, 4):
        sib_in[GEN ** k] = ct[k]
    sib_in[GEN ** 4] = SHAKE_PAD
    for k in unroll(5, 16):
        sib_in[GEN ** k] = 0
    sib_in[GEN ** 16] = LANE_TOP
    sibst = HeapBuf(26)
    sibs = sponge(sib_in, 1, 17, sibst)
    sl = HeapBuf(17)
    state_lanes(sibs, sl, 8, 1)
    signs = HeapBuf(64)
    lane_bits(sl[1], signs)
    sb = HeapBuf(128)
    for l in mul_range(1, GEN ** 16):
        lane_bytes(sl[l * GEN], sb * l ** 8, aux)
    crec = HeapBuf(POLY_CELLS)
    sample_in_ball(sb, signs, aux, crec)

    # z (4 x 256), t1 2^13 (4 x 256) from pk bits 256.., A_hat = ExpandA(rho).
    zr = HeapBuf(4 * POLY_CELLS)
    for k in mul_range(1, GEN ** 1024):
        load_z(zr * k ** REC, tb)
    tbits = HeapBuf(10240)
    for l in mul_range(1, GEN ** 160):
        lane_bits(pk[GEN ** 4 * l], tbits * l ** 64)
    t1r = HeapBuf(4 * POLY_CELLS)
    for k in mul_range(1, GEN ** 1024):
        t1_rec(tbits * k ** 10, t1r * k ** REC, tb)
    am = HeapBuf(16 * POLY_CELLS)
    for r in unroll(0, 4):
        for s in unroll(0, 4):
            rej_ntt_poly(pk, const(s + 256 * r + SHAKE_PAD * 65536), am * GEN ** (POLY_CELLS * (4 * r + s)), aux, tb)

    # w' = NTT^-1(A_hat NTT(z) - NTT(c) NTT(t1 2^d)), row by row.
    zp = HeapBuf(4)
    for i in unroll(0, 4):
        zp[GEN ** i] = ntt(zr * GEN ** (POLY_CELLS * i), tb, zt)
    ch = ntt(crec, tb, zt)
    tp = HeapBuf(4)
    for i in unroll(0, 4):
        tp[GEN ** i] = ntt(t1r * GEN ** (POLY_CELLS * i), tb, zt)
    wv = HeapBuf(4 * POLY_CELLS)
    for j in unroll(0, 4):
        acc = HeapBuf(POLY_CELLS)
        arow = am * GEN ** (4 * POLY_CELLS * j)
        th = tp[GEN ** j]
        for k in mul_range(1, GEN ** 256):
            row_coeff(arow, zp, ch, th, acc, k, tb)
        intt(acc, tb, zt, finv, wv * GEN ** (POLY_CELLS * j))

    # h: at most omega ones.
    hh = HeapBuf(1024)
    hint_witness(hh[0:1024], "ml_h")
    hc = HeapBuf(1025)
    hc[1] = 1
    for k in mul_range(1, GEN ** 1024):
        x = hh[k]
        assert x * x == x
        hc[k * GEN] = hc[k] * (1 + x * (GEN + 1))
    assert log(hc[GEN ** 1024]) < 81

    # c~' = SHAKE256(mu || w1Encode(UseHint(h, w')), 32) must equal c~.
    hin = HeapBuf(119)
    state_lanes(mus, hin, 4, 0)
    for grp in mul_range(1, GEN ** 32):
        encode_group(grp, wv, hh, hin, aux)
    hin[GEN ** 104] = SHAKE_PAD
    for k in unroll(105, 118):
        hin[GEN ** k] = 0
    hin[GEN ** 118] = LANE_TOP
    finst = HeapBuf(13 * 8)
    fin = sponge(hin, 7, 17, finst)
    assert fin[1] == ct[0] + f192(0, 1, 0) * ct[1]
    assert fin[GEN] == ct[2] + f192(0, 1, 0) * ct[3]
    return
