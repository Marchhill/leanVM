# Keccak-f sponges over 64-bit lanes (one K element each), and lane decompositions.
# Lane L of a byte string holds bytes 8L .. 8L+7, little-endian.

SHAKE_PAD = 31


def absorb_block(st, inp, out, rate: Const):
    a = StackBuf(13)
    for c in unroll(0, 8):
        a[c] = st[GEN ** c] + inp[GEN ** (2 * c)] + f192(0, 1, 0) * inp[GEN ** (2 * c + 1)]
    a[8] = st[GEN ** 8] + inp[GEN ** 16]
    if const(rate == 21):
        a[9] = st[GEN ** 9] + inp[GEN ** 17] + f192(0, 1, 0) * inp[GEN ** 18]
        a[10] = st[GEN ** 10] + inp[GEN ** 19] + f192(0, 1, 0) * inp[GEN ** 20]
    else:
        a[9] = st[GEN ** 9]
        a[10] = st[GEN ** 10]
    a[11] = st[GEN ** 11]
    a[12] = st[GEN ** 12]
    keccak_permute(a, out[0:13])
    return


def sponge(lanes, nb: Const, rate: Const, states):
    # Absorbs nb padded blocks from zero; returns the final state (13 cells).
    for k in unroll(0, 13):
        states[GEN ** k] = 0
    for b in mul_range(1, GEN ** nb):
        absorb_block(states * b ** 13, lanes * b ** rate, states * (b * GEN) ** 13, rate)
    return states * GEN ** (13 * nb)


def state_lanes(st, out, pairs: Const, rest: Const):
    # Lanes 0 .. 2 pairs - 1 of a state, then lane 16 (rest >= 1) and 17 .. 20 (rest = 5).
    for c in unroll(0, pairs):
        put_cell(st[GEN ** c], out * GEN ** (2 * c))
    if const(rest != 0):
        out[GEN ** 16] = st[GEN ** 8]
    if const(rest == 5):
        put_cell(st[GEN ** 9], out * GEN ** 17)
        put_cell(st[GEN ** 10], out * GEN ** 19)
    return


def lane_bytes(lane, out, bt):
    # out[0..8) = the lane's bytes as g-powers, little-endian; bt[g^v] = v.
    hint_witness(out[0:8], "bytes")
    acc = 0
    for k in unroll(0, 8):
        v = out[GEN ** k]
        assert log(v) < 256
        acc += bt[v] * COORD_BASIS[8 * k]
    assert acc == lane
    return


def lane_bits(lane, bits):
    hint_decompose_bits(bits, lane, 64)
    acc = 0
    for b in unroll(0, 64):
        x = bits[GEN ** b]
        bits[GEN ** b] = x * x
        acc += x * COORD_BASIS[b]
    assert acc == lane
    return


