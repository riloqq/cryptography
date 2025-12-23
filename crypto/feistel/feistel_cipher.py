from crypto.utility.utility import xor_bytes

class FeistelCipher:
    def __init__(self, key_schedule, round_function, block_size: int = 8, num_rounds: int = 16):
        if block_size % 2 != 0:
            raise ValueError("Block size must be even")
        self.key_schedule = key_schedule
        self.round_function = round_function
        self.block_size = block_size
        self.num_rounds = num_rounds
        self.round_keys = []

    def setup_keys(self, key: bytes) -> None:
        self.round_keys = self.key_schedule.expand_key(key)
        if len(self.round_keys) < self.num_rounds:
            raise ValueError(f"Need at least {self.num_rounds} keys, got {len(self.round_keys)}")

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError(f"Block must be {self.block_size} bytes")
        half = self.block_size // 2
        L = block[:half]
        R = block[half:]
        for i in range(self.num_rounds):
            L_old = L
            L = R
            R = xor_bytes(L_old, self.round_function.apply(R, self.round_keys[i]))
        return L + R

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError(f"Block must be {self.block_size} bytes")
        half = self.block_size // 2
        L, R = block[:half], block[half:]
        for i in range(self.num_rounds - 1, -1, -1):
            temp = L
            L = xor_bytes(R, self.round_function.apply(L, self.round_keys[i]))
            R = temp
        return L + R