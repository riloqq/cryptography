def permute_bits(data: bytes, p_block: list[int],
                 lsb_first: bool = True,
                 start_index: int = 0) -> bytes:
    total_bits = len(data) * 8
    src_value = int.from_bytes(data, byteorder='big')
    result_value = 0

    for out_pos, src_index in enumerate(p_block):
        bit_index = src_index - start_index

        if lsb_first:
            bit = (src_value >> bit_index) & 1
        else:
            bit = (src_value >> (total_bits - 1 - bit_index)) & 1

        result_value |= (bit << (len(p_block) - 1 - out_pos))

    byte_len = (len(p_block) + 7) // 8
    return result_value.to_bytes(byte_len, byteorder='big')
# Исходное значение: 11001010 (0xCA)
data = bytes([0b11001010])

# Правило перестановки (разворот битов)
p_block = [7, 6, 5, 4, 3, 2, 1, 0]

# Проверим обе схемы нумерации
result_msb = permute_bits(data, p_block, lsb_first=False, start_index=0)
result_lsb = permute_bits(data, p_block, lsb_first=True, start_index=0)

# Выводим результаты
print("Исходные данные:")
print(f"  data = {data[0]:08b} (0x{data[0]:02X})")

print("\nПерестановка при lsb_first = False (от старших битов):")
print(f"  результат = {result_msb[0]:08b} (0x{result_msb[0]:02X})")

print("\nПерестановка при lsb_first = True (от младших битов):")
print(f"  результат = {result_lsb[0]:08b} (0x{result_lsb[0]:02X})")

# Ожидаемое поведение:
# - При lsb_first=False: инверсия битов → 01010011 (0x53)
# - При lsb_first=True: порядок сохраняется → 11001010 (0xCA)
