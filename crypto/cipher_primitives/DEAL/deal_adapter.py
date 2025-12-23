from crypto.cipher_primitives.DES.des_cipher import DES

class DESAdapter:
    def apply(self, half_data: bytes, round_key: bytes) -> bytes:
        if len(half_data) != 8:
            raise ValueError("Half data must be 8 bytes")
        if len(round_key) != 8:
            raise ValueError("Round key must be 8 bytes")
        des_inst = DES()
        des_inst.setup_keys(round_key)
        return des_inst.encrypt_block(half_data)