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
    # P_s[k] = g^(s k) for s = 1, 2^12, 2^24, QT0[k] = g^(q k), QT1[k] = g^(2^12 q k), k <= 4096.
    tb[GEN ** P0_OFF] = 1
    tb[GEN ** P1_OFF] = 1
    tb[GEN ** P2_OFF] = 1
    tb[GEN ** QT0_OFF] = 1
    tb[GEN ** QT1_OFF] = 1
    for k in mul_range(1, GEN ** LIMB):
        tb[GEN ** (P0_OFF + 1) * k] = tb[GEN ** P0_OFF * k] * GEN
        tb[GEN ** (P1_OFF + 1) * k] = tb[GEN ** P1_OFF * k] * GEN ** H1
        tb[GEN ** (P2_OFF + 1) * k] = tb[GEN ** P2_OFF * k] * GEN ** H2
        tb[GEN ** (QT0_OFF + 1) * k] = tb[GEN ** QT0_OFF * k] * GEN ** Q_MOD
        tb[GEN ** (QT1_OFF + 1) * k] = tb[GEN ** QT1_OFF * k] * GEN ** (Q_MOD * H1)
    for k in mul_range(GEN ** LIMB, GEN ** Q1_WIDE):
        tb[GEN ** (QT1_OFF + 1) * k] = tb[GEN ** QT1_OFF * k] * GEN ** (Q_MOD * H1)
    return


def tb_squares(tb):
    # F_s[y] = g^(s floor(y^2/4)), stepping F_s[y+1] = F_s[y] P_s[floor((y+1)/2)].
    tb[GEN ** F0_OFF] = 1
    tb[GEN ** F12_OFF] = 1
    tb[GEN ** F24_OFF] = 1
    for k in mul_range(1, GEN ** LIMB):
        k2 = k * k
        for s in unroll(0, 3):
            odd = tb[GEN ** (F0_OFF + s * FT) * k2] * tb[GEN ** (P0_OFF + s * (LIMB + 1)) * k]
            tb[GEN ** (F0_OFF + s * FT + 1) * k2] = odd
            tb[GEN ** (F0_OFF + s * FT + 2) * k2] = odd * tb[GEN ** (P0_OFF + s * (LIMB + 1) + 1) * k]
    for k in mul_range(1, GEN ** (LIMB // 2 + 1)):
        # nk = g^(F_LO - 2 - 2k): the base sits at index -(2k + 2), so every offset is nonnegative.
        nk = GEN ** (F_LO - 2) / (k * k)
        for s in unroll(0, 3):
            odd = tb[GEN ** (s * FT + 2) * nk] * tb[GEN ** (P0_OFF + s * (LIMB + 1)) * k]
            tb[GEN ** (s * FT + 1) * nk] = odd
            tb[GEN ** (s * FT) * nk] = odd * tb[GEN ** (P0_OFF + s * (LIMB + 1) + 1) * k]
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


def ntt_block(sa, da, z0, z1, tb, layer: Const):
    # Cooley-Tukey: t = z b, (a, b) <- (a + t, a - t).
    for j in mul_range(1, GEN ** (2 ** (7 - layer))):
        a = sa * j ** REC
        b = a * GEN ** (REC * 2 ** (7 - layer))
        t = mq_red(mq_prod(z0, z1, b[1], b[GEN], tb), tb)
        ga = a[GEN ** 2]
        u = mq_can(ga * t[2], tb)
        put_rec(da * j ** REC, u)
        v = mq_can(ga * GEN ** (2 * Q_MOD) / t[2], tb)
        put_rec(da * j ** REC * GEN ** (REC * 2 ** (7 - layer)), v)
    return


def ntt_layer(src, dst, tb, zt, layer: Const):
    for b in mul_range(1, GEN ** (2 ** layer)):
        z = zt * (GEN ** (2 ** layer) * b) ** REC
        base = b ** (REC * 2 ** (8 - layer))
        ntt_block(src * base, dst * base, z[1], z[GEN], tb, layer)
    return


def ntt(src, tb, zt):
    # FIPS 204 NTT (Algorithm 41), one fresh array per layer.
    cur = src
    for layer in unroll(0, 8):
        nxt = HeapBuf(POLY_CELLS)
        ntt_layer(cur, nxt, tb, zt, layer)
        cur = nxt
    return cur


def intt_block(sa, da, z0, z1, tb, s: Const):
    # Gentleman-Sande with z = -zeta: (a, b) <- (a + b, zeta (b - a)).
    for j in mul_range(1, GEN ** (2 ** s)):
        a = sa * j ** REC
        b = a * GEN ** (REC * 2 ** s)
        ga = a[GEN ** 2]
        gb = b[GEN ** 2]
        u = mq_can(ga * gb, tb)
        put_rec(da * j ** REC, u)
        d = mq_can(gb * GEN ** (2 * Q_MOD) / ga, tb)
        v = mq_red(mq_prod(z0, z1, d[0], d[1], tb), tb)
        put_rec(da * j ** REC * GEN ** (REC * 2 ** s), v)
    return


def intt_layer(src, dst, tb, zt, s: Const):
    # len = 2^s; block b uses zeta index m = 2^(8-s) - 1 - b.
    for b in mul_range(1, GEN ** (2 ** (7 - s))):
        z = (zt * GEN ** (REC * (2 ** (8 - s) - 1))) / b ** REC
        base = b ** (REC * 2 ** (s + 1))
        intt_block(src * base, dst * base, z[1], z[GEN], tb, s)
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
