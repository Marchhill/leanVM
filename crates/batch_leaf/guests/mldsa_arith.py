# Arithmetic mod q = 8380417 (ML-DSA) in the exponent of g.
#
# A residue is a 3-cell record [g^r0, g^r1, g^r] with r = r0 + 4096 r1, r0 < 4096,
# r1 < 2047, so r < q + 4095: congruent to the intended value mod q, canonical only
# where a caller checks it (`mq_canonical`). Every integer below 2^64 - 1 is its own
# g-power, so g-power products are exact integer sums and equality is integer equality.
#
# Products use quarter squares, a*b = floor((a+b)^2/4) - floor((a-b)^2/4), per 12-bit
# limb pair, read from tables F_s[y] = g^(s floor(y^2/4)) at scales s = 1, 2^12, 2^24.
# A product x < 2^46 is reduced by hinting x = Q q + r with Q, r in limbs and checking
# g^x = g^(Q q) g^r, the limbs range-checked and turned into g-powers by table lookup.

Q_MOD = 8380417
LIMB = 4096
R1_BOUND = 2047
Q1_BOUND = 2049
F_LO = 4098
FT = 12291
F0_OFF = F_LO
F12_OFF = FT + F_LO
F24_OFF = 2 * FT + F_LO
P0_OFF = 3 * FT
P1_OFF = P0_OFF + LIMB + 1
P2_OFF = P1_OFF + LIMB + 1
QT0_OFF = P2_OFF + LIMB + 1
QT1_OFF = QT0_OFF + LIMB + 1
Q1_WIDE = 16384
TB_SIZE = QT1_OFF + Q1_WIDE + 1
REC = 3
POLY_CELLS = 768
H1 = 4096
H2 = 16777216


def tb_powers(tb):
    # P_s[k] = g^(s k) for s = 1, 2^12, 2^24, QT0[k] = g^(q k), QT1[k] = g^(2^12 q k), k <= 4096
    # (QT1 to 16384); four entries per table per iteration.
    tb[GEN ** P0_OFF] = 1
    tb[GEN ** P1_OFF] = 1
    tb[GEN ** P2_OFF] = 1
    tb[GEN ** QT0_OFF] = 1
    tb[GEN ** QT1_OFF] = 1
    for k in mul_range(1, GEN ** (LIMB // 4)):
        k4 = k ** 4
        tb_run(tb * GEN ** P0_OFF * k4, GEN)
        tb_run(tb * GEN ** P1_OFF * k4, GEN ** H1)
        tb_run(tb * GEN ** P2_OFF * k4, GEN ** H2)
        tb_run(tb * GEN ** QT0_OFF * k4, GEN ** Q_MOD)
        tb_run(tb * GEN ** QT1_OFF * k4, GEN ** (Q_MOD * H1))
    for k in mul_range(GEN ** (LIMB // 4), GEN ** (Q1_WIDE // 4)):
        tb_run(tb * GEN ** QT1_OFF * k ** 4, GEN ** (Q_MOD * H1))
    return


@inline
def tb_run(base, h):
    cur = base[1]
    for q in unroll(0, 4):
        cur = cur * h
        base[GEN ** (q + 1)] = cur
    return


@inline
def sq_run(f, p, m4):
    # Four pairs from F[2m] for m = m4 .. m4 + 3, P[m] = h^m: F[2m+1] = F[2m] P[m], F[2m+2] = F[2m+1] P[m+1].
    cur = f[1]
    for q in unroll(0, 4):
        odd = cur * p[GEN ** q]
        f[GEN ** (2 * q + 1)] = odd
        cur = odd * p[GEN ** (q + 1)]
        f[GEN ** (2 * q + 2)] = cur
    return


@inline
def sq_run_neg(f, p, m4):
    # The same downwards; f sits at F[-2 m4 - 8], so offsets stay nonnegative.
    cur = f[GEN ** 8]
    for q in unroll(0, 4):
        odd = cur * p[GEN ** q]
        f[GEN ** (7 - 2 * q)] = odd
        cur = odd * p[GEN ** (q + 1)]
        f[GEN ** (6 - 2 * q)] = cur
    return


def tb_squares(tb):
    # F_s[y] = g^(s floor(y^2/4)), stepping F_s[y+1] = F_s[y] P_s[floor((y+1)/2)].
    tb[GEN ** F0_OFF] = 1
    tb[GEN ** F12_OFF] = 1
    tb[GEN ** F24_OFF] = 1
    for k in mul_range(1, GEN ** (LIMB // 4)):
        k4 = k ** 4
        k8 = k4 * k4
        for s in unroll(0, 3):
            sq_run(tb * GEN ** (F0_OFF + s * FT) * k8, tb * GEN ** (P0_OFF + s * (LIMB + 1)) * k4, k4)
    for k in mul_range(1, GEN ** (LIMB // 8)):
        k4 = k ** 4
        nk = GEN ** (F_LO - 8) / (k4 * k4)
        for s in unroll(0, 3):
            sq_run_neg(tb * nk * GEN ** (s * FT), tb * GEN ** (P0_OFF + s * (LIMB + 1)) * k4, k4)
    return


def build_tables():
    tb = HeapBuf(TB_SIZE)
    tb_powers(tb)
    tb_squares(tb)
    return tb


@inline
def mq_prod(a0, a1, b0, b1, tb):
    # g^(a b) for limbs a = a0 + 2^12 a1, b = b0 + 2^12 b1 (as g-powers).
    f0 = tb * GEN ** F0_OFF
    f12 = tb * GEN ** F12_OFF
    f24 = tb * GEN ** F24_OFF
    p = f0[a0 * b0] / f0[a0 / b0] * f12[a0 * b1] / f12[a0 / b1]
    return p * f12[a1 * b0] / f12[a1 / b0] * f24[a1 * b1] / f24[a1 / b1]


@inline
def mq_red(p, tb):
    # p = g^x, x < 2^46: the record [g^r0, g^r1, g^r] of r = x mod q.
    h = StackBuf(5)
    hint_witness(h[0:2], "mq")
    hint_witness(h[3:5], "mqq")
    assert log(h[0]) < LIMB
    assert log(h[1]) < R1_BOUND
    assert log(h[3]) < LIMB
    assert log(h[4]) < Q1_BOUND
    h[2] = h[0] * tb[GEN ** P1_OFF * h[1]]
    assert p == tb[GEN ** QT0_OFF * h[3]] * tb[GEN ** QT1_OFF * h[4]] * h[2]
    return h


@inline
def mq_red_wide(p, tb):
    # p = g^x, x < 2^49: as mq_red, with a quotient below 2^26.
    h = StackBuf(5)
    hint_witness(h[0:2], "mq")
    hint_witness(h[3:5], "mqq")
    assert log(h[0]) < LIMB
    assert log(h[1]) < R1_BOUND
    assert log(h[3]) < LIMB
    assert log(h[4]) < Q1_WIDE
    h[2] = h[0] * tb[GEN ** P1_OFF * h[1]]
    assert p == tb[GEN ** QT0_OFF * h[3]] * tb[GEN ** QT1_OFF * h[4]] * h[2]
    return h


@inline
def mq_can(s, tb):
    # s = g^x, x < 4q: the record of x mod q.
    h = StackBuf(3)
    hint_witness(h[0:2], "ma")
    assert log(h[0]) < LIMB
    assert log(h[1]) < R1_BOUND
    h[2] = h[0] * tb[GEN ** P1_OFF * h[1]]
    d = s / h[2]
    assert (d + 1) * (d + GEN ** Q_MOD) * (d + GEN ** (2 * Q_MOD)) * (d + GEN ** (3 * Q_MOD)) == 0
    return h


@inline
def put_rec(dst, r):
    dst[1] = r[0]
    dst[GEN] = r[1]
    dst[GEN ** 2] = r[2]
    return


def mq_load(out, tb):
    # A hinted residue (stream "mv"), as a record.
    h = StackBuf(2)
    hint_witness(h, "mv")
    assert log(h[0]) < LIMB
    assert log(h[1]) < R1_BOUND
    out[1] = h[0]
    out[GEN] = h[1]
    out[GEN ** 2] = h[0] * tb[GEN ** P1_OFF * h[1]]
    return


def mq_mul(a, b, out, tb):
    r = mq_red(mq_prod(a[1], a[GEN], b[1], b[GEN], tb), tb)
    put_rec(out, r)
    return


def mq_add(a, b, out, tb):
    r = mq_can(a[GEN ** 2] * b[GEN ** 2], tb)
    put_rec(out, r)
    return


def mq_sub(a, b, out, tb):
    r = mq_can(a[GEN ** 2] * GEN ** (2 * Q_MOD) / b[GEN ** 2], tb)
    put_rec(out, r)
    return


@inline
def ct_one(a, da, z0, z1, tb, off):
    # Cooley-Tukey at a / a * off: t = z b, (a, b) <- (a + t, a - t).
    b = a * off
    t = mq_red(mq_prod(z0, z1, b[1], b[GEN], tb), tb)
    ga = a[GEN ** 2]
    u = mq_can(ga * t[2], tb)
    put_rec(da, u)
    v = mq_can(ga * GEN ** (2 * Q_MOD) / t[2], tb)
    put_rec(da * off, v)
    return


def ct_run(sa, da, z0, z1, tb, npairs_g, off):
    # One block of len = 2 npairs butterflies, two per iteration; off = g^(REC len).
    for j in mul_range(1, npairs_g):
        o = j ** (2 * REC)
        ct_one(sa * o, da * o, z0, z1, tb, off)
        ct_one(sa * o * GEN ** REC, da * o * GEN ** REC, z0, z1, tb, off)
    return


def ntt_layer(src, dst, tb, zt, layer: Const):
    if const(layer != 7):
        for b in mul_range(1, GEN ** (2 ** layer)):
            z = zt * (GEN ** (2 ** layer) * b) ** REC
            base = b ** (REC * 2 ** (8 - layer))
            ct_run(src * base, dst * base, z[1], z[GEN], tb, GEN ** (2 ** (6 - layer)), GEN ** (REC * 2 ** (7 - layer)))
    else:
        # len 1: two blocks, each with its own zeta, per iteration.
        for b in mul_range(1, GEN ** 64):
            z = zt * (GEN ** 128 * b * b) ** REC
            base = b ** (4 * REC)
            ct_one(src * base, dst * base, z[1], z[GEN], tb, GEN ** REC)
            z2 = z * GEN ** REC
            ct_one(src * base * GEN ** (2 * REC), dst * base * GEN ** (2 * REC), z2[1], z2[GEN], tb, GEN ** REC)
    return


def ntt(src, tb, zt):
    # FIPS 204 NTT (Algorithm 41), one fresh array per layer.
    cur = src
    for layer in unroll(0, 8):
        nxt = HeapBuf(POLY_CELLS)
        ntt_layer(cur, nxt, tb, zt, layer)
        cur = nxt
    return cur


@inline
def gs_one(a, da, z0, z1, tb, off, last: Const):
    # Gentleman-Sande with z = -zeta: (a, b) <- (a + b, zeta (b - a)). Only the last layer's
    # outputs need limbs (the scaling multiplies them); earlier ones keep just g^r.
    b = a * off
    ga = a[GEN ** 2]
    gb = b[GEN ** 2]
    u = mq_can(ga * gb, tb)
    d = mq_can(gb * GEN ** (2 * Q_MOD) / ga, tb)
    v = mq_red(mq_prod(z0, z1, d[0], d[1], tb), tb)
    if const(last == 1):
        put_rec(da, u)
        put_rec(da * off, v)
    else:
        da[GEN ** 2] = u[2]
        (da * off)[GEN ** 2] = v[2]
    return


def gs_run(sa, da, z0, z1, tb, npairs_g, off, last: Const):
    for j in mul_range(1, npairs_g):
        o = j ** (2 * REC)
        gs_one(sa * o, da * o, z0, z1, tb, off, last)
        gs_one(sa * o * GEN ** REC, da * o * GEN ** REC, z0, z1, tb, off, last)
    return


def intt_layer(src, dst, tb, zt, s: Const):
    # len = 2^s; block b uses zeta index m = 2^(8-s) - 1 - b.
    if const(s != 0):
        for b in mul_range(1, GEN ** (2 ** (7 - s))):
            z = (zt * GEN ** (REC * (2 ** (8 - s) - 1))) / b ** REC
            base = b ** (REC * 2 ** (s + 1))
            gs_run(src * base, dst * base, z[1], z[GEN], tb, GEN ** (2 ** (s - 1)), GEN ** (REC * 2 ** s), s // 7)
    else:
        for b in mul_range(1, GEN ** 64):
            z = (zt * GEN ** (REC * 255)) / (b * b) ** REC
            base = b ** (4 * REC)
            gs_one(src * base, dst * base, z[1], z[GEN], tb, GEN ** REC, 0)
            z2 = z / GEN ** REC
            gs_one(src * base * GEN ** (2 * REC), dst * base * GEN ** (2 * REC), z2[1], z2[GEN], tb, GEN ** REC, 0)
    return


def intt(src, tb, zt, finv, out):
    # FIPS 204 NTT^-1 (Algorithm 42), then the scaling by 256^-1.
    cur = src
    for s in unroll(0, 8):
        nxt = HeapBuf(POLY_CELLS)
        intt_layer(cur, nxt, tb, zt, s)
        cur = nxt
    for k in mul_range(1, GEN ** 256):
        mq_mul(finv, cur * k ** REC, out * k ** REC, tb)
    return
