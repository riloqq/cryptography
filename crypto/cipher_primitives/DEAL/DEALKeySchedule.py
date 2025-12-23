from crypto.cipher_primitives.DES.des_cipher import DES
from crypto.utility.utility import xor_bytes

class DEALKeySchedule:
    CONSTANT_KEY = bytes.fromhex("1234567890abcdef")

    def __init__(self, key_bits: int = 128):
        if key_bits not in (128, 192, 256):
            raise ValueError("Key bits must be 128, 192, or 256")
        self.key_bits = key_bits
        self.key_bytes = key_bits // 8
        self.num_rounds = 6 if key_bits in (128, 192) else 8
        self.num_key_parts = key_bits // 64


    def _create_bit_mask(self, bit_pos: int) -> bytes:
        if not 1 <= bit_pos <= 64:
            raise ValueError("Bit pos between 1 and 64")
        mask_int = 1 << (64 - bit_pos)
        return mask_int.to_bytes(8, "big")

    def expand_key(self, master_key: bytes) -> list[bytes]:
        if len(master_key) != self.key_bytes:
            raise ValueError(f"Key must be {self.key_bytes} bytes")
        key_parts = [master_key[i:i+8] for i in range(0, len(master_key), 8)]
        des_inst = DES()
        des_inst.setup_keys(self.CONSTANT_KEY)
        E = des_inst.encrypt_block
        round_keys = []
        if self.key_bits == 128:
            K1, K2 = key_parts
            RK1 = E(K1)
            round_keys.append(RK1)
            RK2 = E(xor_bytes(K2, RK1))
            round_keys.append(RK2)
            RK3 = E(xor_bytes(K1, self._create_bit_mask(1)))
            round_keys.append(RK3)
            RK4 = E(xor_bytes(xor_bytes(K2, self._create_bit_mask(1)), RK3))
            round_keys.append(RK4)
            RK5 = E(xor_bytes(xor_bytes(K1, self._create_bit_mask(2)), RK4))
            round_keys.append(RK5)
            RK6 = E(xor_bytes(xor_bytes(K2, self._create_bit_mask(4)), RK5))
            round_keys.append(RK6)
        elif self.key_bits == 192:
            K1, K2, K3 = key_parts
            RK1 = E(K1)
            round_keys.append(RK1)
            RK2 = E(xor_bytes(K2, RK1))
            round_keys.append(RK2)
            RK3 = E(xor_bytes(xor_bytes(K1, self._create_bit_mask(1)), RK2))
            round_keys.append(RK3)
            RK4 = E(xor_bytes(xor_bytes(K2, self._create_bit_mask(1)), RK3))
            round_keys.append(RK4)
            RK5 = E(xor_bytes(xor_bytes(K1, self._create_bit_mask(2)), RK4))
            round_keys.append(RK5)
            RK6 = E(xor_bytes(xor_bytes(K3, self._create_bit_mask(4)), RK5))
            round_keys.append(RK6)
        elif self.key_bits == 256:
            K1, K2, K3, K4 = key_parts
            RK1 = E(K1)
            round_keys.append(RK1)
            RK2 = E(xor_bytes(K2, RK1))
            round_keys.append(RK2)
            RK3 = E(xor_bytes(K3, RK2))
            round_keys.append(RK3)
            RK4 = E(xor_bytes(K4, RK3))
            round_keys.append(RK4)
            RK5 = E(xor_bytes(xor_bytes(K1, self._create_bit_mask(1)), RK4))
            round_keys.append(RK5)
            RK6 = E(xor_bytes(xor_bytes(K2, self._create_bit_mask(2)), RK5))
            round_keys.append(RK6)
            RK7 = E(xor_bytes(xor_bytes(K3, self._create_bit_mask(4)), RK6))
            round_keys.append(RK7)
            RK8 = E(xor_bytes(xor_bytes(K4, self._create_bit_mask(8)), RK7))
            round_keys.append(RK8)
        return round_keys