def bitperm(input_data: bytes, perm_block: list[int], msb_first: bool = True, one_based_indexing: bool = True) -> bytes:
    total_bits = len(input_data) * 8
    result_int = 0
    for perm_idx in perm_block:
        src_pos = perm_idx - 1 if one_based_indexing else perm_idx
        if not 0 <= src_pos < total_bits:
            raise IndexError(f"Pos {src_pos} out of range")
        byte_pos = src_pos // 8
        bit_pos = src_pos % 8
        src_byte = input_data[byte_pos]
        bit_shift = 7 - bit_pos if msb_first else bit_pos
        bit_value = (src_byte >> bit_shift) & 1
        result_int = (result_int << 1) | bit_value
    output_bits = len(perm_block)
    output_bytes = (output_bits + 7) // 8
    padding_bits = output_bytes * 8 - output_bits
    result_int <<= padding_bits
    return result_int.to_bytes(output_bytes, "big")