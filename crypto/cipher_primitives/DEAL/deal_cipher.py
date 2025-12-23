from crypto.cipher_primitives.DEAL.DEALKeySchedule import DEALKeySchedule
from crypto.cipher_primitives.DEAL.deal_adapter import DESAdapter
from crypto.feistel.feistel_cipher import FeistelCipher

class DEAL(FeistelCipher):
    BLOCK_SIZE_BYTES = 16

    def __init__(self, key_bits: int = 128):
        if key_bits not in (128, 192, 256):
            raise ValueError("Key bits must be 128, 192, or 256")
        self.key_bits = key_bits
        num_rounds = 6 if key_bits in (128, 192) else 8
        key_scheduler = DEALKeySchedule(key_bits)
        round_func = DESAdapter()
        super().__init__(key_scheduler, round_func, block_size=self.BLOCK_SIZE_BYTES, num_rounds=num_rounds)