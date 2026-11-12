# ML-DSA-44 inside a WebAuthn assertion (COSE alg -48): the credential signs
# authenticatorData || SHA-256(clientDataJSON), authenticatorData = rpIdHash || flags || signCount.
# claim = Keccak-256(CLAIM_TAG || pk || challenge || rpIdHash || policy || origin_len || origin),
# policy the required flags (UP | UV) as a 16-byte cell, origin zero-padded to 64 bytes and its
# length as a 16-byte cell. Checked, in WebAuthn's fixed serialization order: clientDataJSON
# starts {"type":"webauthn.get","challenge":"<base64url(challenge)>","origin":"<origin>",
# then "crossOrigin":false or no crossOrigin member, and no "topOrigin": member next; the rpIdHash and the flags.
# Members after crossOrigin are hashed, not read.

WA_TAG_0 = WA_TAG_0_PLACEHOLDER
WA_TAG_1 = WA_TAG_1_PLACEHOLDER
WA_POLICY = 5
WA_PREFIX = WA_PREFIX_PLACEHOLDER
WA_PREFIX_LEN = 36
WA_ORIGIN_KEY = WA_ORIGIN_KEY_PLACEHOLDER
WA_CROSS = WA_CROSS_PLACEHOLDER
WA_TOP = WA_TOP_PLACEHOLDER
WA_CROSS_KEY = WA_CROSS_KEY_PLACEHOLDER
WA_ORIGIN_AT = 91
WA_ORIGIN_MAX = 64
WA_CLOSE = WA_CLOSE_PLACEHOLDER
WA_COMMA = WA_COMMA_PLACEHOLDER
WA_MAX_BLOCKS = 6
WA_QUOTE = WA_QUOTE_PLACEHOLDER
WA_B64_PAIRS = WA_B64_PAIRS_PLACEHOLDER
WA_B64_D0 = WA_B64_D0_PLACEHOLDER
WA_B64_D1 = WA_B64_D1_PLACEHOLDER
WA_KT_PAIRS = WA_KT_PAIRS_PLACEHOLDER
WA_KT_D0 = WA_KT_D0_PLACEHOLDER
WA_KT_D1 = WA_KT_D1_PLACEHOLDER
SHA_IVG = SHA_IVG_PLACEHOLDER
# wa layout: base64url VALID then value bits 0..5 (256 each), 2^8 b, 2^16 b, 2^24 b, K
WA_S8 = 1792
WA_S16 = 2048
WA_S24 = 2304
WA_KT = 2560
WA_SIZE = 2624


def setup_scheme():
    m = mldsa_setup()
    wa = HeapBuf(WA_SIZE)
    load_checked(wa, GEN ** WA_B64_PAIRS, WA_B64_D0, WA_B64_D1)
    load_checked(wa * GEN ** WA_KT, GEN ** WA_KT_PAIRS, WA_KT_D0, WA_KT_D1)
    wa[GEN ** WA_S8] = 1
    wa[GEN ** WA_S16] = 1
    wa[GEN ** WA_S24] = 1
    for b in mul_range(1, GEN ** 255):
        wa[GEN ** (WA_S8 + 1) * b] = wa[GEN ** WA_S8 * b] * GEN ** 256
        wa[GEN ** (WA_S16 + 1) * b] = wa[GEN ** WA_S16 * b] * GEN ** 65536
        wa[GEN ** (WA_S24 + 1) * b] = wa[GEN ** WA_S24 * b] * GEN ** 16777216
    ctx = HeapBuf(2)
    ctx[1] = m
    ctx[GEN] = wa
    return ctx


def wa_block(pb, b, st, kt, wa):
    blk = HeapBuf(528)
    bytes = pb * b ** 64
    for w in unroll(0, 16):
        gw = wa[GEN ** WA_S24 * bytes[GEN ** (4 * w)]] * wa[GEN ** WA_S16 * bytes[GEN ** (4 * w + 1)]]
        gw = gw * wa[GEN ** WA_S8 * bytes[GEN ** (4 * w + 2)]] * bytes[GEN ** (4 * w + 3)]
        word_bits(gw, blk * GEN ** (WREC * w))
    sha256_compress(st * b ** 264, blk, st * (b * GEN) ** 264, kt)
    return


def verify_claim(ctx):
    m = ctx[1]
    wa = ctx[GEN]
    aux = m[GEN]

    pk = HeapBuf(170)
    hint_witness(pk[0:164], "ml_pk")
    for k in mul_range(1, GEN ** 82):
        assert_in_k(pk[k * k], pk[k * k * GEN])
    pk[GEN ** 164] = SHAKE_PAD
    for k in unroll(165, 169):
        pk[GEN ** k] = 0
    pk[GEN ** 169] = LANE_TOP
    ch = StackBuf(2)
    hint_witness(ch, "wa_challenge")
    rp = StackBuf(2)
    hint_witness(rp, "wa_rp")

    # claim: tag(2) pk(164) challenge(4) rpIdHash(4) policy(2) = 176 lanes, 11 blocks.
    cl = HeapBuf(187)
    cl[1] = WA_TAG_0
    cl[GEN] = WA_TAG_1
    for k in mul_range(1, GEN ** 164):
        cl[GEN ** 2 * k] = pk[k]
    put_cell(ch[0], cl * GEN ** 166)
    put_cell(ch[1], cl * GEN ** 168)
    put_cell(rp[0], cl * GEN ** 170)
    put_cell(rp[1], cl * GEN ** 172)
    cl[GEN ** 174] = WA_POLICY
    cl[GEN ** 175] = 0

    # clientDataJSON as nb padded SHA-256 blocks of byte g-powers.
    nb = hint_witness("wa_nb")
    assert log(nb) < WA_MAX_BLOCKS + 1
    assert nb != 1
    lg = hint_witness("wa_len")
    pb = HeapBuf(64 * WA_MAX_BLOCKS)
    for b in mul_range(1, nb):
        blk = pb * b ** 64
        hint_witness(blk[0:64], "wa_bytes")
    end_g = nb ** 64
    for p in mul_range(1, end_g):
        assert log(pb[p]) < 256
    # padding: 0x80 at L, zeros, then the bit length 8 L big-endian in the last 8 bytes.
    zc = end_g / GEN ** 9 / lg
    assert log(zc) < 64
    pb[lg] = GEN ** 128
    for t in mul_range(1, zc):
        pb[lg * GEN * t] = 1
    tail = pb * end_g / GEN ** 8
    for k in unroll(0, 6):
        tail[GEN ** k] = 1
    assert tail[GEN ** 6] ** 256 * tail[GEN ** 7] == lg ** 8

    # type and challenge: the fixed prefix, 43 base64url characters, a quote.
    for i in unroll(0, WA_PREFIX_LEN):
        assert pb[GEN ** i] == WA_PREFIX[i]
    c0 = 0
    c1 = 0
    for c in unroll(0, 43):
        chg = pb[GEN ** (WA_PREFIX_LEN + c)]
        assert wa[chg] == 1
        for k in unroll(0, 6):
            bitv = wa[GEN ** (256 * (1 + k)) * chg]
            if const((6 * c + 5 - k) // 128 == 0):
                c0 = c0 + bitv * COORD_BASIS[8 * ((6 * c + 5 - k) // 8) + 7 - (6 * c + 5 - k) % 8]
            elif const((6 * c + 5 - k) // 128 == 1):
                c1 = c1 + bitv * COORD_BASIS[8 * ((6 * c + 5 - k - 128) // 8) + 7 - (6 * c + 5 - k) % 8]
            else:
                assert bitv == 0
    assert c0 == ch[0]
    assert c1 == ch[1]
    assert pb[GEN ** (WA_PREFIX_LEN + 43)] == WA_QUOTE

    # ,"origin":"<origin>" with the origin copied, zero-padded, into the claim.
    for i in unroll(0, 11):
        assert pb[GEN ** (WA_PREFIX_LEN + 44 + i)] == WA_ORIGIN_KEY[i]
    lo = hint_witness("wa_origin_len")
    assert log(lo) < WA_ORIGIN_MAX + 1
    ob = HeapBuf(WA_ORIGIN_MAX)
    hint_witness(ob[0:WA_ORIGIN_MAX], "wa_origin")
    src = pb * GEN ** WA_ORIGIN_AT
    for j in mul_range(1, lo):
        assert ob[j] == src[j]
    for j in mul_range(1, GEN ** WA_ORIGIN_MAX / lo):
        assert ob[lo * j] == 1
    after = src * lo
    assert after[1] == WA_QUOTE
    # Then "}", or "," and either "crossOrigin":false (then "}" or "," not before "topOrigin":)
    # or, crossOrigin absent, a member other than "topOrigin":.
    c1 = after[GEN]
    if c1 == WA_CLOSE:
        assert lg == lo * GEN ** (WA_ORIGIN_AT + 2)
    else:
        assert c1 == WA_COMMA
        key = 0
        for i in unroll(0, 14):
            key = key + aux[GEN ** BT_OFF * after[GEN ** (2 + i)]] * COORD_BASIS[8 * i]
        # A jump condition must be a 64-bit word, so branch on a hinted flag checked against key.
        is_cross = hint_witness("wa_is_cross")
        if is_cross == 1:
            assert key == WA_CROSS_KEY
            for i in unroll(15, 20):
                assert after[GEN ** (1 + i)] == WA_CROSS[i]
            nxt = after[GEN ** 21]
            if nxt == WA_CLOSE:
                assert lg == lo * GEN ** (WA_ORIGIN_AT + 22)
            else:
                assert nxt == WA_COMMA
                pat = 0
                for i in unroll(0, 12):
                    pat = pat + aux[GEN ** BT_OFF * after[GEN ** (22 + i)]] * COORD_BASIS[8 * i]
                assert pat != WA_TOP
        else:
            assert key != WA_CROSS_KEY
            pat = 0
            for i in unroll(0, 12):
                pat = pat + aux[GEN ** BT_OFF * after[GEN ** (2 + i)]] * COORD_BASIS[8 * i]
            assert pat != WA_TOP
    cl[GEN ** 176] = aux[GEN ** BT_OFF * lo]
    cl[GEN ** 177] = 0
    for w in unroll(0, 8):
        lanew = 0
        for k in unroll(0, 8):
            lanew = lanew + aux[GEN ** BT_OFF * ob[GEN ** (8 * w + k)]] * COORD_BASIS[8 * k]
        cl[GEN ** (178 + w)] = lanew
    cl[GEN ** 186] = LANE_TOP + 1
    cls = HeapBuf(13 * 12)
    claim = sponge(cl, 11, 17, cls)

    # SHA-256(clientDataJSON)
    kt = wa * GEN ** WA_KT
    st = HeapBuf(264 * (WA_MAX_BLOCKS + 1))
    for i in unroll(0, 8):
        word_bits(SHA_IVG[i], st * GEN ** (WREC * i))
    for b in mul_range(1, nb):
        wa_block(pb, b, st, kt, wa)
    hd = st * nb ** 264

    # authenticatorData: rpIdHash, flags (UP and UV required), signCount.
    rl = HeapBuf(4)
    put_cell(rp[0], rl)
    put_cell(rp[1], rl * GEN ** 2)
    rb = HeapBuf(32)
    for k in unroll(0, 4):
        lane_bytes(rl[GEN ** k], rb * GEN ** (8 * k), aux)
    fb = StackBuf(8)
    hint_witness(fb, "wa_flags")
    flags = 0
    for i in unroll(0, 8):
        fb[i] = fb[i] * fb[i]
        flags = flags + fb[i] * COORD_BASIS[i]
    assert fb[0] == 1
    assert fb[2] == 1
    sc = StackBuf(4)
    hint_witness(sc, "wa_count")
    for i in unroll(0, 4):
        assert log(sc[i]) < 256

    # mu input: tr || 0x00 0x00 || authData (37) || hash (32); M byte p at mu byte 66 + p.
    mu_in = HeapBuf(17)
    for lane in unroll(8, 17):
        acc = 0
        for p in unroll(0, 69):
            if const((66 + p) // 8 == lane):
                if const(p // 32 == 0):
                    pat = aux[GEN ** BT_OFF * rb[GEN ** p]]
                elif const(p == 32):
                    pat = flags
                elif const((p - 33) // 4 == 0):
                    pat = aux[GEN ** BT_OFF * sc[p - 33]]
                else:
                    word = hd * GEN ** (WREC * ((p - 37) // 4))
                    pat = 0
                    for q in unroll(0, 8):
                        pat = pat + word[GEN ** (8 * (3 - (p - 37) % 4) + q)] * COORD_BASIS[q]
                acc = acc + pat * COORD_BASIS[8 * ((66 + p) % 8)]
        if const(lane == 16):
            acc = acc + const(159 * 2 ** 56)
        mu_in[GEN ** lane] = acc
    mldsa_core(m, pk, mu_in)
    return claim[1], claim[GEN]
