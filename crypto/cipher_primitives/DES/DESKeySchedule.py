from crypto.utility.bitperm import bitperm

MASK_28 = (1 << 28) - 1


class DESKeySchedule:
    PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
           63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
    PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47,
           55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
    SHIFT_TABLE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    def expand_key(self, master_key: bytes) -> list[bytes]:
        if len(master_key) == 7:
            master_key = self._insert_parity(master_key)
        elif len(master_key) != 8:
            raise ValueError("Key must be 7 or 8 bytes")
        permuted_key = bitperm(master_key, self.PC1, msb_first=True, one_based_indexing=True)
        left_half = int.from_bytes(permuted_key[:4], "big") >> 4
        right_half = int.from_bytes(permuted_key[3:], "big") & MASK_28
        round_keys = []
        for shift_idx in range(16):
            left_half = self._left_rotate_28(left_half, self.SHIFT_TABLE[shift_idx])
            right_half = self._left_rotate_28(right_half, self.SHIFT_TABLE[shift_idx])
            combined_halves = ((left_half << 28) | right_half).to_bytes(7, "big")
            round_key = bitperm(combined_halves, self.PC2, msb_first=True, one_based_indexing=True)
            round_keys.append(round_key)
        return round_keys

    def _left_rotate_28(self, value: int, shift_amount: int) -> int:
        return ((value << shift_amount) | (value >> (28 - shift_amount))) & MASK_28

    def _insert_parity(self, key_56: bytes) -> bytes:
        if len(key_56) != 7:
            raise ValueError("Key must be 7 bytes")
        key_int = int.from_bytes(key_56, "big")
        result_bytes = bytearray()
        for byte_idx in range(8):
            shift_amount = 56 - (byte_idx + 1) * 7
            seven_bits = (key_int >> shift_amount) & 0b01111111
            parity_count = bin(seven_bits).count("1")
            parity_bit = 1 if parity_count % 2 == 0 else 0
            byte_with_parity = (seven_bits << 1) | parity_bit
            result_bytes.append(byte_with_parity)
        return bytes(result_bytes)
