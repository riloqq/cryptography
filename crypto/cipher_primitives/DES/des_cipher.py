from crypto.utility.bitperm import bitperm
from crypto.cipher_primitives.DES.DESKeySchedule import DESKeySchedule
from crypto.cipher_primitives.DES.DESRoundFunction import DESRoundFunction
from crypto.feistel.feistel_cipher import FeistelCipher


class DES(FeistelCipher):
    IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
    FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

    def __init__(self):
        key_scheduler = DESKeySchedule()
        round_func = DESRoundFunction()
        super().__init__(key_scheduler, round_func, block_size=8, num_rounds=16)

    def encrypt_block(self, data_block: bytes) -> bytes:
        if len(data_block) != 8:
            raise ValueError("Block size must be 8 bytes")
        permuted_block = bitperm(data_block, self.IP, msb_first=True, one_based_indexing=True)
        feistel_result = super().encrypt_block(permuted_block)
        left_part = feistel_result[:4]
        right_part = feistel_result[4:]
        pre_final = right_part + left_part
        final_cipher = bitperm(pre_final, self.FP, msb_first=True, one_based_indexing=True)
        return final_cipher

    def decrypt_block(self, data_block: bytes) -> bytes:
        if len(data_block) != 8:
            raise ValueError("Block size must be 8 bytes")
        permuted_block = bitperm(data_block, self.IP, msb_first=True, one_based_indexing=True)
        left_part, right_part = permuted_block[:4], permuted_block[4:]
        core_input = right_part + left_part
        core_result = super().decrypt_block(core_input)
        final_plain = bitperm(core_result, self.FP, msb_first=True, one_based_indexing=True)
        return final_plain
