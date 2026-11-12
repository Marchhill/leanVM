# Falcon-512 (round 3, PQClean raw-message mode) claim:
# claim = Keccak-256(CLAIM_TAG || M || pk), M 32 bytes, pk the 897-byte encoded key.
#
# Arithmetic mod q = 12289 in the exponent of g: a residue r < q is the single cell g^r,
# products by quarter squares F[y] = g^(floor(y^2/4)) and an exact hinted reduction,
# both operands below q so every range check is one gadget. The signature is a
# witness: s2 is taken as its coefficients (|s2_i| <= 2047, no "-0", the compressed
# format's coefficient range), not as the compressed string.

CLAIM_TAG_0 = CLAIM_TAG_0_PLACEHOLDER
CLAIM_TAG_1 = CLAIM_TAG_1_PLACEHOLDER
FQ = 12289
FN = 512
F_NEG = 12288
F_OFF = F_NEG
F_SIZE = 36867
QT_OFF = F_SIZE
TB_SIZE = QT_OFF + FQ
# aux: byte bit patterns, then 256^v
FBT_OFF = 0
FS256_OFF = 256
FAUX_SIZE = 512
NORM_BOUND = 34034726
FBT = FBT_PLACEHOLDER
FZT = FZT_PLACEHOLDER
FNINV = FNINV_PLACEHOLDER


def fq_tables(tb):
    # F[y] for y in [-12288, 24577]: F[y + 1] = F[y] g^floor((y+1)/2); QT[k] = g^(q k).
    f = tb * GEN ** F_OFF
    f[1] = 1
    for k in mul_range(1, GEN ** 12289):
        k2 = k * k
        odd = f[k2] * k
        f[k2 * GEN] = odd
        f[k2 * GEN ** 2] = odd * k * GEN
    for k in mul_range(1, GEN ** 6144):
        nk = GEN ** (F_NEG - 2) / (k * k)
        odd = tb[nk * GEN ** 2] * k
        tb[nk * GEN] = odd
        tb[nk] = odd * k * GEN
    qt = tb * GEN ** QT_OFF
    qt[1] = 1
    for k in mul_range(1, GEN ** (FQ - 1)):
        qt[k * GEN] = qt[k] * GEN ** FQ
    return


def setup_scheme():
    tb = HeapBuf(TB_SIZE)
    fq_tables(tb)
    aux = HeapBuf(FAUX_SIZE)
    for v in unroll(0, 256):
        aux[GEN ** (FBT_OFF + v)] = FBT[v]
    aux[GEN ** FS256_OFF] = 1
    for v in mul_range(1, GEN ** 255):
        aux[GEN ** (FS256_OFF + 1) * v] = aux[GEN ** FS256_OFF * v] * GEN ** 256
    zt = HeapBuf(FN)
    for k in unroll(0, FN):
        zt[GEN ** k] = FZT[k]
    ctx = HeapBuf(3)
    # The F table's centre as a stored pointer: F[y] = tb[g^y] for negative y too.
    fb = tb * GEN ** F_OFF
    ctx[1] = fb
    ctx[GEN] = aux
    ctx[GEN ** 2] = zt
    return ctx


@inline
def fq_mul(a, b, tb):
    p = tb[(a * b)] / tb[(a / b)]
    h = StackBuf(2)
    hint_witness(h, "fq")
    assert log(h[0]) < FQ
    assert log(h[1]) < FQ
    assert p == h[0] * tb[GEN ** (QT_OFF - F_OFF) * h[1]]
    return h[0]


@inline
def fq_can(s):
    # s = g^x with x < 2q: g^(x mod q).
    r = hint_witness("fa")
    assert log(r) < FQ
    d = s / r
    assert (d + 1) * (d + GEN ** FQ) == 0
    return r


def fntt_block(sa, da, z, tb, layer: Const):
    for j in mul_range(1, GEN ** (2 ** (8 - layer))):
        a = sa[j]
        t = fq_mul(z, sa[j * GEN ** (2 ** (8 - layer))], tb)
        da[j] = fq_can(a * t)
        da[j * GEN ** (2 ** (8 - layer))] = fq_can(a * GEN ** FQ / t)
    return


def fntt(src, tb, zt):
    cur = src
    for layer in unroll(0, 9):
        nxt = HeapBuf(FN)
        for b in mul_range(1, GEN ** (2 ** layer)):
            base = b ** (2 ** (9 - layer))
            fntt_block(cur * base, nxt * base, zt[GEN ** (2 ** layer) * b], tb, layer)
        cur = nxt
    return cur


def fintt_block(sa, da, z, tb, s: Const):
    for j in mul_range(1, GEN ** (2 ** s)):
        a = sa[j]
        b = sa[j * GEN ** (2 ** s)]
        da[j] = fq_can(a * b)
        da[j * GEN ** (2 ** s)] = fq_mul(z, fq_can(b * GEN ** FQ / a), tb)
    return


def fintt(src, tb, zt, out):
    cur = src
    for s in unroll(0, 9):
        nxt = HeapBuf(FN)
        for b in mul_range(1, GEN ** (2 ** (8 - s))):
            base = b ** (2 ** (s + 1))
            fintt_block(cur * base, nxt * base, zt[GEN ** (2 ** (9 - s) - 1) / b], tb, s)
        cur = nxt
    for k in mul_range(1, GEN ** FN):
        out[k] = fq_mul(FNINV, cur[k], tb)
    return


def htp_sample(w, ci, nc, cvec, tb):
    # One HashToPoint sample: accepted iff w < 5 q, then c[ci] = w mod q.
    acc = hint_witness("htp_acc")
    if acc == 1:
        kc = StackBuf(2)
        hint_witness(kc, "htp_kc")
        assert log(kc[0]) < 5
        assert log(kc[1]) < FQ
        assert w == kc[1] * tb[GEN ** (QT_OFF - F_OFF) * kc[0]]
        cvec[ci] = kc[1]
        nc[1] = ci * GEN
    else:
        assert log(w / GEN ** 61445) < 4091
        nc[1] = ci
    return


def h_group(grp, bits, hp):
    # Four 14-bit coefficients, most significant bit first, from pk bytes 1 + 7 grp ..
    base = bits * grp ** 56 * GEN ** 8
    for c in unroll(0, 4):
        acc = 1
        for t in unroll(0, 14):
            sb = 14 * c + t
            acc = acc * (1 + base[GEN ** (8 * (sb // 8) + 7 - sb % 8)] * (GEN ** (2 ** (13 - t)) + 1))
        assert log(acc) < FQ
        hp[grp ** 4 * GEN ** c] = acc
    return


def verify_claim(ctx):
    tb = ctx[1]
    aux = ctx[GEN]
    zt = ctx[GEN ** 2]

    # pk: 112 lanes, then the 897th byte alone; M and the 40-byte nonce.
    pk = HeapBuf(113)
    hint_witness(pk[0:112], "fa_pk")
    for k in mul_range(1, GEN ** 56):
        assert_in_k(pk[k * k], pk[k * k * GEN])
    lastb = hint_witness("fa_pk_last")
    assert log(lastb) < 256
    pk[GEN ** 112] = aux[GEN ** FBT_OFF * lastb]
    msg = StackBuf(4)
    hint_witness(msg, "fa_msg")
    assert_in_k(msg[0], msg[1])
    assert_in_k(msg[2], msg[3])
    nonce = StackBuf(5)
    hint_witness(nonce, "fa_nonce")
    assert_in_k(nonce[0], nonce[1])
    assert_in_k(nonce[2], nonce[3])
    assert_in_k(nonce[4], 0)

    # claim = Keccak-256(tag || M || pk): 945 bytes, 7 blocks; pad bytes share lane 118.
    cl = HeapBuf(119)
    cl[1] = CLAIM_TAG_0
    cl[GEN] = CLAIM_TAG_1
    for k in unroll(0, 4):
        cl[GEN ** (2 + k)] = msg[k]
    for k in mul_range(1, GEN ** 112):
        cl[GEN ** 6 * k] = pk[k]
    cl[GEN ** 118] = pk[GEN ** 112] + const(256 + 2 ** 63)
    cls = HeapBuf(13 * 8)
    claim = sponge(cl, 7, 17, cls)

    # h from the key bits; byte 0 is the header 0x09.
    bits = HeapBuf(113 * 64)
    for l in mul_range(1, GEN ** 113):
        lane_bits(pk[l], bits * l ** 64)
    hdr = 0
    for i in unroll(0, 8):
        hdr += bits[GEN ** i] * COORD_BASIS[i]
    assert hdr == 9
    hp = HeapBuf(FN)
    for grp in mul_range(1, GEN ** 128):
        h_group(grp, bits, hp)

    # c = HashToPoint(nonce || M): 16-bit big-endian samples below 5q, reduced.
    hl = HeapBuf(17)
    for k in unroll(0, 5):
        hl[GEN ** k] = nonce[k]
    for k in unroll(0, 4):
        hl[GEN ** (5 + k)] = msg[k]
    hl[GEN ** 9] = SHAKE_PAD
    for k in unroll(10, 16):
        hl[GEN ** k] = 0
    hl[GEN ** 16] = LANE_TOP
    nb = hint_witness("htp_nb")
    assert log(nb) < 16
    st = HeapBuf(13 * 17)
    st1 = sponge(hl, 1, 17, st)
    for b in mul_range(GEN, nb):
        nxt = StackBuf(13)
        cur = st * b ** 13
        for k in unroll(0, 13):
            nxt[k] = cur[GEN ** k]
        keccak_permute(nxt, (st * (b * GEN) ** 13)[0:13])
    by = HeapBuf(136 * 15)
    for b in mul_range(1, nb):
        sl = HeapBuf(17)
        state_lanes(st * (b * GEN) ** 13, sl, 8, 1)
        bb = by * b ** 136
        for l in mul_range(1, GEN ** 17):
            lane_bytes(sl[l], bb * l ** 8, aux)
    ns = hint_witness("htp_n")
    assert log(ns) < log(nb ** 68)
    cvec = HeapBuf(FN)
    cur = HeapBuf(1021)
    cur[1] = 1
    for s in mul_range(1, ns):
        two = by * s ** 2
        htp_sample(aux[GEN ** FS256_OFF * two[1]] * two[GEN], cur[s], cur * s * GEN, cvec, tb)
    assert cur[ns] == GEN ** FN

    # s2 = (-1)^sg m with m <= 2047, no "-0"; its squared norm.
    s2 = HeapBuf(FN)
    n2 = HeapBuf(FN + 1)
    n2[1] = 1
    for k in mul_range(1, GEN ** FN):
        h = StackBuf(3)
        hint_witness(h, "fa_s2")
        assert log(h[0]) < 2048
        h[1] = h[1] * h[1]
        assert log(h[2]) < FQ
        assert h[2] == h[0] + h[1] * (GEN ** FQ / h[0] + h[0])
        s2[k] = h[2]
        n2[k * GEN] = n2[k] * tb[(h[0] * h[0])]

    # s1 = c - s2 h mod q, centered; ||s1||^2 + ||s2||^2 <= floor(beta^2).
    sh = fntt(s2, tb, zt)
    hh = fntt(hp, tb, zt)
    pr = HeapBuf(FN)
    for k in mul_range(1, GEN ** FN):
        pr[k] = fq_mul(sh[k], hh[k], tb)
    p = HeapBuf(FN)
    fintt(pr, tb, zt, p)
    n1 = HeapBuf(FN + 1)
    n1[1] = 1
    for k in mul_range(1, GEN ** FN):
        r = fq_can(cvec[k] * GEN ** FQ / p[k])
        big = hint_witness("fa_big")
        if big == 1:
            assert log(r / GEN ** 6145) < 6144
            n1[k * GEN] = n1[k] * tb[(GEN ** FQ / r) ** 2]
        else:
            assert log(r) < 6145
            n1[k * GEN] = n1[k] * tb[r ** 2]
    d = StackBuf(2)
    hint_witness(d, "fa_slack")
    assert log(d[0]) < 65536
    assert log(d[1]) < 65536
    assert n1[GEN ** FN] * n2[GEN ** FN] * d[0] * d[1] ** 65536 == GEN ** NORM_BOUND
    return claim[1], claim[GEN]
