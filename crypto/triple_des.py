from crypto.cipher_primitives.DES.des_cipher import DES


class TripleDES:
    block_bytes = 8

    def __init__(self, des_mode: str = "EDE"):
        if des_mode not in ("EDE", "EEE"):
            raise ValueError("Mode EDE or EEE")
        self.des_mode = des_mode
        self._des_one = DES()
        self._des_two = DES()
        self._des_three = DES()
        self._three_key = False

    def setup_keys(self, triple_key: bytes) -> None:
        key_len = len(triple_key)
        if key_len not in (14, 16, 21, 24):
            raise ValueError("Key 14,16,21,24 bytes")
        if key_len in (21, 24):
            k1, k2, k3 = triple_key[0:7 if key_len==21 else 8], triple_key[7 if key_len==21 else 8:14 if key_len==21 else 16], triple_key[14 if key_len==21 else 16:21 if key_len==21 else 24]
            self._three_key = True
        else:
            k1, k2 = triple_key[0:7 if key_len==14 else 8], triple_key[7 if key_len==14 else 8:14 if key_len==14 else 16]
            k3 = k1
            self._three_key = False
        self._des_one.setup_keys(k1)
        self._des_two.setup_keys(k2)
        self._des_three.setup_keys(k3)

    def encrypt_block(self, data_block: bytes) -> bytes:
        if len(data_block) != self.block_bytes:
            raise ValueError("Block 8 bytes")
        if self.des_mode == "EDE":
            b1 = self._des_one.encrypt_block(data_block)
            b2 = self._des_two.decrypt_block(b1)
            b3 = self._des_three.encrypt_block(b2)
        else:
            b1 = self._des_one.encrypt_block(data_block)
            b2 = self._des_two.encrypt_block(b1)
            b3 = self._des_three.encrypt_block(b2)
        return b3

    def decrypt_block(self, data_block: bytes) -> bytes:
        if len(data_block) != self.block_bytes:
            raise ValueError("Block 8 bytes")
        if self.des_mode == "EDE":
            b1 = self._des_three.decrypt_block(data_block)
            b2 = self._des_two.encrypt_block(b1)
            b3 = self._des_one.decrypt_block(b2)
        else:
            b1 = self._des_three.decrypt_block(data_block)
            b2 = self._des_two.decrypt_block(b1)
            b3 = self._des_one.decrypt_block(b2)
        return b3