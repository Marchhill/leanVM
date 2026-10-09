def checked_byte(x, table):
    index = hint_witness("byte_index")
    assert log(index) < 256
    assert table[index] == x
    return


def word(raw, start: Const, n: Const):
    x = 0
    for j in unroll(0, n):
        x += raw[GEN ** (start + j)] * 2 ** (8 * j)
    return x

def operand_power(raw, start: Const, width: Const, powers):
    low = hint_witness("operand_index")
    high = hint_witness("operand_index")
    assert log(low) < 256
    assert log(high) < 256
    assert powers[low] == raw[GEN ** start]
    assert powers[high] == raw[GEN ** (start + 1)]
    for j in unroll(2, width):
        assert raw[GEN ** (start + j)] == 0
    return powers[GEN ** 256 * low] * powers[GEN ** 512 * high]

def table_counter(block_g, powers):
    low = hint_witness("counter_index")
    high = hint_witness("counter_index")
    assert log(low) < 256
    assert log(high) < 256
    assert powers[GEN ** 256 * low] * powers[GEN ** 512 * high] == block_g
    return (powers[low] + powers[high] * 256) * 64

def columns(op: Const, raw, at, squares, powers, c):
    a = StackBuf(4)
    k = StackBuf(3)
    for j in unroll(0, 4):
        a[j] = word(raw * at, 1 + 4 * j, 4)
    for j in unroll(0, 3):
        k[j] = word(raw * at, 17 + 8 * j, 8)
    md = word(raw * at, 41, 4)
    c[GEN ** (0)] = OPCODES[op]
    if op == 0:
        for j in unroll(0, 3):
            c[GEN ** (j + 1)] = operand_power(raw * at, 1 + 4 * j, 4, powers)
        assert a[3] == 0
        for j in unroll(0, 3):
            assert k[j] == 0
        assert md == 0
        for j in unroll(4, 12):
            c[GEN ** (j)] = 0
    elif op == 1:
        for j in unroll(0, 3):
            c[GEN ** (j + 1)] = operand_power(raw * at, 1 + 4 * j, 4, powers)
        assert a[3] == 0
        for j in unroll(0, 3):
            assert k[j] == 0
        assert md == 0
        for j in unroll(4, 12):
            c[GEN ** (j)] = 0
    elif op == 4:
        for j in unroll(0, 3):
            c[GEN ** (j + 1)] = operand_power(raw * at, 1 + 4 * j, 4, powers)
        assert a[3] == 0
        for j in unroll(0, 3):
            assert k[j] == 0
        assert md == 0
        for j in unroll(4, 12):
            c[GEN ** (j)] = 0
    elif op == 2:
        c[GEN ** (1)] = operand_power(raw * at, 1, 4, powers)
        c[GEN ** (2)] = k[0]
        c[GEN ** (3)] = k[1]
        c[GEN ** (4)] = k[2]
        for j in unroll(1, 4):
            assert a[j] == 0
        assert md == 0
        for j in unroll(5, 12):
            c[GEN ** (j)] = 0
    elif op == 3:
        for j in unroll(0, 3):
            c[GEN ** (j + 1)] = operand_power(raw * at, 1 + 4 * j, 4, powers)
        mode_checked = match(log(g_power_of_word(a[3], squares, 2)), range(0, 3), lambda mode: mode_flags(mode, c))
        for j in unroll(0, 3):
            assert k[j] == 0
        assert md == 0
        for j in unroll(6, 12):
            c[GEN ** (j)] = 0
    elif op == 5:
        for j in unroll(0, 4):
            c[GEN ** (j + 1)] = operand_power(raw * at, 1 + 4 * j, 4, powers)
        c[GEN ** (5)] = operand_power(raw * at, 17, 8, powers)
        c[GEN ** (6)] = operand_power(raw * at, 25, 8, powers)
        c[GEN ** (7)] = operand_power(raw * at, 41, 4, powers)
        assert k[2] == 0
        for j in unroll(8, 12):
            c[GEN ** (j)] = 0
    else:
        for j in unroll(0, 4):
            c[GEN ** (j + 1)] = operand_power(raw * at, 1 + 4 * j, 4, powers)
        for j in unroll(0, 6):
            c[GEN ** (j + 5)] = operand_power(raw * at, 17 + 4 * j, 4, powers)
        # cap/out cannot address beyond the native operand boundary.
        assert log(c[GEN ** (9)]) < 65532
        assert log(c[GEN ** (10)]) < 65524
        assert md * md == md
        c[GEN ** (11)] = md
    return 0

def mode_flags(mode: Const, c):
    if mode == 0:
        c[GEN ** 4] = 0
        c[GEN ** 5] = 0
    elif mode == 1:
        c[GEN ** 4] = 1
        c[GEN ** 5] = 0
    else:
        c[GEN ** 4] = 0
        c[GEN ** 5] = 1
    return 0


def mixed_keccak(raw, length_g, squares):
    byte_table = HeapBuf(256)
    for i in unroll(0, 256):
        byte_table[GEN ** i] = i
    split = StackBuf(2)
    hint_witness(split, "keccak_split")
    blocks_g = split[0]
    tail_g = split[1]
    assert log(blocks_g) < 5423
    assert log(tail_g) < 136
    assert blocks_g ** 136 * tail_g == length_g
    padded_g = (blocks_g * GEN) ** 136
    if length_g == padded_g / GEN:
        raw[length_g] = 129
    else:
        raw[length_g] = 1
        mixed_bound_0 = length_g * GEN
        mixed_bound_1 = padded_g / GEN / mixed_bound_0
        for pos in mul_range(1, mixed_bound_1):
            raw[mixed_bound_0 * pos] = 0
        raw[padded_g / GEN] = 128
    states = HeapBuf((blocks_g * GEN ** 2) ** 13)
    for i in unroll(0, 13):
        states[GEN ** i] = 0
    mixed_bound_2 = blocks_g * GEN
    for block in mul_range(1, mixed_bound_2):
        input = raw * block ** 136
        state = states * block ** 13
        lanes = StackBuf(17)
        for lane in unroll(0, 17):
            value = 0
            for byte in unroll(0, 8):
                b = input[GEN ** (8 * lane + byte)]
                if b != 0:
                    checked_byte(b, byte_table)
                value += b * 2 ** (8 * byte)
            lanes[lane] = value
        absorbed = StackBuf(13)
        for i in unroll(0, 8):
            absorbed[i] = state[GEN ** i] + pack64x2(lanes[2 * i], lanes[2 * i + 1])
        absorbed[8] = state[GEN ** 8] + lanes[16]
        for i in unroll(9, 13):
            absorbed[i] = state[GEN ** i]
        keccak_permute(absorbed, (states * (block * GEN) ** 13)[0:13])
    digest = StackBuf(2)
    final = states * (blocks_g * GEN) ** 13
    digest[0] = final[1]
    digest[1] = final[GEN]
    return digest


def dynamic_eqtree(point, output, code_log_g, squares):
    output[1] = 1
    for level in mul_range(1, code_log_g):
        width_g = squares[level]
        start_g = width_g / GEN
        next_g = width_g ** 2 / GEN
        r = point[level]
        for row in mul_range(1, width_g):
            prior = output[start_g * row]
            output[next_g * row] = prior * (1 + r)
            output[next_g * width_g * row] = prior * r
    return


def mixed_cell_bytes(value, output, table):
    hint_witness(output[0:16], "cell_bytes")
    reconstructed = 0
    for i in unroll(0, 16):
        index = hint_witness("cell_index")
        assert log(index) < 256
        byte = output[GEN ** i]
        assert table[index] == byte
        reconstructed += byte * COORD_BASIS[8 * i]
    assert reconstructed == value
    return


def mixed_generic(logs, squares, fresh):
    program_log = hint_witness("program_log")
    code_log_g = g_power_of_word(program_log, squares, 4)
    assert log(code_log_g) < MAX_GENERIC_CODE_LOG + 1
    size_g = squares[code_log_g]
    length_g = GEN ** 4 * size_g ** 45
    raw = HeapBuf(length_g * GEN ** 136)
    hint_witness(raw[0:4], "code_header")
    assert g_power_of_word(word(raw, 0, 4), squares, 15) == size_g
    for row in mul_range(1, size_g):
        instruction = raw * GEN ** 4 * row ** 45
        hint_witness(instruction[0:45], "code_instruction")
    vk = mixed_keccak(raw, length_g, squares)
    powers = HeapBuf(768)
    for i in unroll(0, 256):
        powers[GEN ** i] = i
        powers[GEN ** (256 + i)] = GEN ** i
        powers[GEN ** (512 + i)] = GEN ** (256 * i)
    table = HeapBuf(size_g ** 16)
    for slot in unroll(0, 3):
        for row in mul_range(1, size_g):
            table[size_g ** slot * row] = 0
    for row in mul_range(1, size_g):
        instruction = raw * GEN ** 4 * row ** 45
        opcode = g_power_of_word(instruction[1], squares, 3)
        c = HeapBuf(12)
        done = match(log(opcode), range(0, 7), lambda op: columns(op, instruction, 1, squares, powers, c))
        for column in unroll(0, 12):
            table[size_g ** (3 + column) * row] = c[GEN ** column]
        table[size_g ** 15 * row] = 0
    hashes = HeapBuf(size_g ** 4 * GEN ** 2)
    hashes[1] = MIXED_BLAKE_IV_0
    hashes[GEN] = MIXED_BLAKE_IV_1
    mixed_bound_3 = size_g ** 2
    for block in mul_range(1, mixed_bound_3):
        input = table * block ** 8
        state = hashes * block ** 2
        output = hashes * (block * GEN) ** 2
        counter = table_counter(block * GEN, powers)
        md = StackBuf(1)
        if block * GEN == size_g ** 2:
            md[0] = counter + MD_FINAL
        else:
            md[0] = counter
        packed = StackBuf(4)
        for i in unroll(0, 4):
            packed[i] = pack64x2(input[GEN ** (2 * i)], input[GEN ** (2 * i + 1)])
        blake2s(packed[0:2], packed[2:4], output[0:2], cv=[state[1], state[GEN]], md=md[0])
    table_digest = hashes * size_g ** 4
    seed0, seed1 = mixed_program_seed(table_digest)
    data = StackBuf(2)
    hint_witness(data, "generic_data")
    canonical0 = assert_canonical(data[0])
    canonical1 = assert_canonical(data[1])
    actual = HeapBuf(DEFER_SIZE)
    verify_sub(data[0], data[1], seed0, seed1, logs, squares, actual, code_log_g, GEN ** GENERIC_COMMITTED_LOG, GEN ** GENERIC_BUS_LOG)
    row_eq = HeapBuf(size_g ** 2 / GEN)
    dynamic_eqtree(actual, row_eq, code_log_g, squares)
    slot_eq = HeapBuf(30)
    eqtree(actual * GEN ** BYTECODE_LOG, slot_eq, 4)
    values = HeapBuf(size_g * GEN)
    values[1] = 0
    for row in mul_range(1, size_g):
        total = 0
        for slot in unroll(3, 15):
            total += table[size_g ** slot * row] * slot_eq[GEN ** (14 + slot)]
        values[row * GEN] = values[row] + total * row_eq[size_g / GEN * row]
    assert values[size_g] == actual[GEN ** FRESH_BC_VALUE]
    for i in unroll(0, BYTECODE_VARS):
        fresh[GEN ** i] = 0
    fresh[GEN ** FRESH_BC_VALUE] = 0
    for i in unroll(FRESH_FLOCK, DEFER_SIZE):
        fresh[GEN ** i] = actual[GEN ** i]
    claim = HeapBuf(6)
    claim[1] = 0
    claim[GEN] = f192(0, 1224979098644774912, 0)
    claim[GEN ** 2] = data[0]
    claim[GEN ** 3] = data[1]
    claim[GEN ** 4] = vk[0]
    claim[GEN ** 5] = vk[1]
    return claim, data[0], data[1]


def mixed_list_digest(entries, count_g, powers):
    # EIP-8288 get_deps_hash: BLAKE2s over each entry's data hash and key, one 64-byte block each.
    digest = StackBuf(2)
    if count_g == 1:
        blake2s([0, 0], [0, 0], digest, md=MD_FINAL)
    else:
        states = HeapBuf((count_g * GEN) ** 2)
        states[1] = BLAKE2S_IV_0
        states[GEN] = BLAKE2S_IV_1
        for block in mul_range(1, count_g):
            entry = entries * block ** 6
            state = states * block ** 2
            output = states * (block * GEN) ** 2
            counter = table_counter(block * GEN, powers)
            md = StackBuf(1)
            if block * GEN == count_g:
                md[0] = counter + MD_FINAL
            else:
                md[0] = counter
            blake2s(entry[2:4], entry[4:6], output[0:2], cv=[state[1], state[GEN]], md=md[0])
        final = states * count_g ** 2
        digest[0] = final[1]
        digest[1] = final[GEN]
    return digest


def mixed_dependencies(n_g, powers):
    # SPHINCS entries, then generic ones, as canonical order sorts them. Without generic
    # entries the digest is get_deps_hash; otherwise both lists' digests are hashed with
    # a domain block, a 96-byte preimage that no 64n-byte list shares.
    assert log(n_g) < MAX_MIXED_DEPENDENCIES + 1
    split = StackBuf(2)
    hint_witness(split, "dependency_split")
    ns_g = split[0]
    nt_g = split[1]
    assert log(ns_g) < MAX_MIXED_DEPENDENCIES + 1
    assert log(nt_g) < MAX_MIXED_GENERIC + 1
    assert ns_g * nt_g == n_g
    entries = HeapBuf(n_g ** 6)
    for row in mul_range(1, ns_g):
        entry = entries * row ** 6
        hint_witness(entry[0:6], "dependency")
        assert entry[1] == 0
        assert entry[GEN] == f192(0, 1152921504606846976, 0)
    generic = entries * ns_g ** 6
    for row in mul_range(1, nt_g):
        entry = generic * row ** 6
        hint_witness(entry[0:6], "dependency")
        assert entry[1] == 0
        assert entry[GEN] == f192(0, 1224979098644774912, 0)
    sphincs = mixed_list_digest(entries, ns_g, powers)
    digest = StackBuf(2)
    if nt_g == 1:
        digest[0] = sphincs[0]
        digest[1] = sphincs[1]
    else:
        stark = mixed_list_digest(generic, nt_g, powers)
        joined = StackBuf(2)
        blake2s([sphincs[0], sphincs[1]], [stark[0], stark[1]], joined, counter=64, final=0)
        blake2s([LEANSTARK_DEPS_DOMAIN_0, LEANSTARK_DEPS_DOMAIN_1], [0, 0], digest, cv=joined, counter=96, final=1)
    return entries, digest[0], digest[1]


def mixed_cover(claim, selected, count_g, covered, mark):
    selection = StackBuf(2)
    hint_witness(selection, "selection")
    keep = selection[0]
    assert keep * keep == keep
    if keep == 1:
        index = selection[1]
        assert log(index) < log(count_g)
        expected = selected * index ** 6
        for i in unroll(0, 6):
            assert claim[GEN ** i] == expected[GEN ** i]
        covered[index] = mark
        return mark * GEN
    return mark


def mixed_leaf(defer, values):
    for i in unroll(0, BYTECODE_VARS):
        defer[GEN ** i] = 0
    defer[GEN ** DEFER_STMT_BC_VALUE] = values[GEN ** 0]
    for i in unroll(0, 2 * K_LOG):
        defer[GEN ** (DEFER_STMT_MAT + i)] = 0
    defer[GEN ** (DEFER_STMT_MAT + 2 * K_LOG)] = values[GEN ** 1]
    defer[GEN ** (DEFER_STMT_MAT + 2 * K_LOG + 1)] = values[GEN ** 2]
    for i in unroll(0, 2 * K_LOG_K):
        defer[GEN ** (DEFER_STMT_MAT_K + i)] = 0
    defer[GEN ** (DEFER_STMT_MAT_K + 2 * K_LOG_K)] = values[GEN ** 3]
    defer[GEN ** (DEFER_STMT_MAT_K + 2 * K_LOG_K + 1)] = values[GEN ** 4]
    return


def main():
    logs, squares = exponent_tables()
    meta = StackBuf(4)
    hint_witness(meta, "mixed_meta")
    n_g = meta[0]
    ns_g = meta[1]
    ng_g = meta[2]
    nc_g = meta[3]
    assert log(n_g) < MAX_MIXED_DEPENDENCIES + 1
    assert log(ns_g) < 5
    assert log(ng_g) < 2
    assert log(nc_g) < 3
    if nc_g != 1:
        assert ns_g == 1
        assert ng_g == 1
    elif ng_g != 1:
        assert ns_g == 1
    seed = StackBuf(2)
    hint_witness(seed, "fs_seed")
    checked0 = assert_canonical(seed[0])
    checked1 = assert_canonical(seed[1])
    seed0 = seed[0]
    seed1 = seed[1]
    powers = HeapBuf(768)
    for i in unroll(0, 256):
        powers[GEN ** i] = i
        powers[GEN ** (256 + i)] = GEN ** i
        powers[GEN ** (512 + i)] = GEN ** (256 * i)
    selected, hash0, hash1 = mixed_dependencies(n_g, powers)
    selected_hash = HeapBuf(2)
    selected_hash[1] = hash0
    selected_hash[GEN] = hash1
    covered = HeapBuf(n_g)
    leaf_values = HeapBuf(5)
    hint_witness(leaf_values[0:5], "leaf_defer")
    raw_marks = HeapBuf(ns_g * GEN)
    raw_marks[1] = 1
    for raw in mul_range(1, ns_g):
        signer = HeapBuf(4)
        hint_witness(signer[0:4], "raw_sph_claim")
        verify_sig_sphincs(signer)
        # EIP-8288: a SPHINCS key is its own 32-byte verification key, root then public parameter.
        claim = HeapBuf(6)
        claim[1] = 0
        claim[GEN] = f192(0, 1152921504606846976, 0)
        claim[GEN ** 2] = signer[1]
        claim[GEN ** 3] = signer[GEN]
        claim[GEN ** 4] = signer[GEN ** 2]
        claim[GEN ** 5] = signer[GEN ** 3]
        raw_marks[raw * GEN] = mixed_cover(claim, selected, n_g, covered, raw_marks[raw])
    origins_g = ng_g * nc_g
    fresh = HeapBuf(origins_g ** DEFER_SIZE)
    carried = HeapBuf(origins_g ** DEFER_STMT_CELLS)
    inputs = HeapBuf(origins_g ** 2)
    generic_marks = HeapBuf(ng_g * GEN)
    generic_marks[1] = raw_marks[ns_g]
    for generic in mul_range(1, ng_g):
        claim, pi0, pi1 = mixed_generic(logs, squares, fresh * generic ** DEFER_SIZE)
        inputs[generic ** 2] = pi0
        inputs[generic ** 2 * GEN] = pi1
        mixed_leaf(carried * generic ** DEFER_STMT_CELLS, leaf_values)
        generic_marks[generic * GEN] = mixed_cover(claim, selected, n_g, covered, generic_marks[generic])
    child_marks = HeapBuf(nc_g * GEN)
    child_marks[1] = generic_marks[ng_g]
    for child in mul_range(1, nc_g):
        count_g = hint_witness("child_count")
        deps, h0, h1 = mixed_dependencies(count_g, powers)
        row_marks = HeapBuf(count_g * GEN)
        row_marks[1] = child_marks[child]
        for row in mul_range(1, count_g):
            row_marks[row * GEN] = mixed_cover(deps * row ** 6, selected, n_g, covered, row_marks[row])
        child_marks[child * GEN] = row_marks[count_g]
        origin = ng_g * child
        current = carried * origin ** DEFER_STMT_CELLS
        hint_witness(current[0:DEFER_STMT_CELLS], "child_carried")
        digest = HeapBuf(2)
        digest[1] = h0
        digest[GEN] = h1
        pi0, pi1 = statement_digest(seed0, seed1, digest, 0, 0, current)
        inputs[origin ** 2] = pi0
        inputs[origin ** 2 * GEN] = pi1
        verify_sub(pi0, pi1, seed0, seed1, logs, squares, fresh * origin ** DEFER_SIZE, GEN ** BYTECODE_LOG, GEN ** MIXED_COMMITTED_LOG, GEN ** MIXED_BUS_LOG)
    assert child_marks[nc_g] == n_g
    own = HeapBuf(DEFER_STMT_CELLS)
    if origins_g == 1:
        mixed_leaf(own, leaf_values)
    else:
        aggregate_claims(origins_g, inputs, fresh, carried, own)
    pi0, pi1 = statement_digest(seed0, seed1, selected_hash, 0, 0, own)
    public = 1
    assert public[1] == pi0
    assert public[GEN] == pi1
    return
