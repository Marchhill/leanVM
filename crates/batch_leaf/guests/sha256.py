# SHA-256 compression in software: leanVM has no SHA-256 instruction. A 32-bit word is a
# 33-cell record: its bits (0/1 cells, bit i at cell i) then g^w. Bitwise functions act on
# bits (XOR is field addition), sums mod 2^32 on g-powers with a hinted carry, and the
# exponent-to-bits step uses computed advice re-checked by recomposition.

WREC = 33


def word_bits(gw, rec):
    # rec = bits and g-power of the 32-bit w with g^w = gw.
    hint_decompose_bits_exponent(rec, gw, 32)
    acc = 1
    for i in unroll(0, 32):
        b = rec[GEN ** i]
        rec[GEN ** i] = b * b
        acc = acc * (1 + b * (GEN ** (2 ** i) + 1))
    assert acc == gw
    rec[GEN ** 32] = gw
    return


def add_mod(s, rec):
    # s = g^x with x a sum of at most 8 words: rec = x mod 2^32. Any carry bound works:
    # a wrong carry leaves a remainder outside [0, 2^32), which the 32-bit recomposition rejects.
    c = hint_witness("sha_c")
    assert log(c) < 8
    word_bits(s / (c ** 65536) ** 65536, rec)
    return


def big_sigma(x, r1: Const, r2: Const, r3: Const):
    acc = 1
    for i in unroll(0, 32):
        v = x[GEN ** ((i + r1) % 32)] + x[GEN ** ((i + r2) % 32)] + x[GEN ** ((i + r3) % 32)]
        acc = acc * (1 + v * (GEN ** (2 ** i) + 1))
    return acc


def small_sigma(x, r1: Const, r2: Const, s: Const):
    acc = 1
    for i in unroll(0, 32 - s):
        v = x[GEN ** ((i + r1) % 32)] + x[GEN ** ((i + r2) % 32)] + x[GEN ** (i + s)]
        acc = acc * (1 + v * (GEN ** (2 ** i) + 1))
    for i in unroll(32 - s, 32):
        v = x[GEN ** ((i + r1) % 32)] + x[GEN ** ((i + r2) % 32)]
        acc = acc * (1 + v * (GEN ** (2 ** i) + 1))
    return acc


def ch_exp(e, f, g):
    acc = 1
    for i in unroll(0, 32):
        gi = g[GEN ** i]
        acc = acc * (1 + (gi + e[GEN ** i] * (f[GEN ** i] + gi)) * (GEN ** (2 ** i) + 1))
    return acc


def maj_exp(a, b, c):
    acc = 1
    for i in unroll(0, 32):
        ai = a[GEN ** i]
        bi = b[GEN ** i]
        acc = acc * (1 + (ai * bi + c[GEN ** i] * (ai + bi)) * (GEN ** (2 ** i) + 1))
    return acc


def sha256_compress(state, block, out, kt):
    # state, out: 8 word records; block: 16 word records (big-endian words as integers).
    w = HeapBuf(64 * WREC)
    for t in mul_range(1, GEN ** 16):
        src = block * t ** WREC
        dst = w * t ** WREC
        for i in unroll(0, WREC):
            dst[GEN ** i] = src[GEN ** i]
    for t in mul_range(GEN ** 16, GEN ** 64):
        w2 = w * (t / GEN ** 2) ** WREC
        w7 = w * (t / GEN ** 7) ** WREC
        w15 = w * (t / GEN ** 15) ** WREC
        w16 = w * (t / GEN ** 16) ** WREC
        s = small_sigma(w2, 17, 19, 10) * w7[GEN ** 32] * small_sigma(w15, 7, 18, 3) * w16[GEN ** 32]
        add_mod(s, w * t ** WREC)
    # A[t + 4], E[t + 4] are a and e after round t; slots 0..3 hold the initial d, c, b, a / h, g, f, e.
    av = HeapBuf(68 * WREC)
    ev = HeapBuf(68 * WREC)
    for i in unroll(0, 4):
        for j in unroll(0, WREC):
            av[GEN ** (WREC * (3 - i) + j)] = state[GEN ** (WREC * i + j)]
            ev[GEN ** (WREC * (3 - i) + j)] = state[GEN ** (WREC * (4 + i) + j)]
    for t in mul_range(1, GEN ** 64):
        a = av * (t * GEN ** 3) ** WREC
        b = av * (t * GEN ** 2) ** WREC
        c = av * (t * GEN) ** WREC
        d = av * t ** WREC
        e = ev * (t * GEN ** 3) ** WREC
        f = ev * (t * GEN ** 2) ** WREC
        g = ev * (t * GEN) ** WREC
        h = ev * t ** WREC
        wt = w * t ** WREC
        t1 = h[GEN ** 32] * big_sigma(e, 6, 11, 25) * ch_exp(e, f, g) * kt[t] * wt[GEN ** 32]
        add_mod(d[GEN ** 32] * t1, ev * (t * GEN ** 4) ** WREC)
        add_mod(t1 * big_sigma(a, 2, 13, 22) * maj_exp(a, b, c), av * (t * GEN ** 4) ** WREC)
    for i in unroll(0, 4):
        add_mod(state[GEN ** (WREC * i + 32)] * av[GEN ** (WREC * (67 - i) + 32)], out * GEN ** (WREC * i))
        add_mod(state[GEN ** (WREC * (4 + i) + 32)] * ev[GEN ** (WREC * (67 - i) + 32)], out * GEN ** (WREC * (4 + i)))
    return
