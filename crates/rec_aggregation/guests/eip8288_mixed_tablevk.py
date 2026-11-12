def mixed_generic(logs, squares, fresh):
    # Benchmark variant (EIP8288_TABLE_VK): the key is the program's Fiat-Shamir seed, which
    # already commits to the bytecode table, so the table is hinted directly instead of
    # being decoded from a Keccak-hashed canonical code encoding.
    program_log = hint_witness("program_log")
    code_log_g = g_power_of_word(program_log, squares, 4)
    assert log(code_log_g) < MAX_GENERIC_CODE_LOG + 1
    size_g = squares[code_log_g]
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
        c = StackBuf(12)
        hint_witness(c, "table_row")
        for column in unroll(0, 12):
            table[size_g ** (3 + column) * row] = c[column]
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
    claims, count_g = mixed_batch(data[0], data[1], seed0, seed1, squares)
    return claims, count_g, data[0], data[1]
