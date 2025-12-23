import secrets
from typing import BinaryIO
from .base_mode import BaseCipherMode
from crypto.utility.utility import apply_padding, remove_padding, split_into_blocks, xor_bytes

class PCBCMode(BaseCipherMode):
    def _decrypt_worker(self, data_block: bytes):
        return self.cipher_primitive.decrypt_block(data_block)

    def encrypt_data(self, input_data: bytes) -> bytes:
        block_size = self.cipher_block_size
        padded_data = apply_padding(input_data, block_size, self.cipher_padding)
        init_vector = self.cipher_iv if self.cipher_iv else secrets.token_bytes(block_size)
        prev_cipher = init_vector
        prev_plain = b"\x00" * block_size
        output_data = [init_vector]
        for plain_block in split_into_blocks(padded_data, block_size):
            xor_input = xor_bytes(plain_block, xor_bytes(prev_plain, prev_cipher))
            encrypted_block = self.cipher_primitive.encrypt_block(xor_input)
            output_data.append(encrypted_block)
            prev_plain, prev_cipher = plain_block, encrypted_block
        return b"".join(output_data)

    def decrypt_data(self, input_data: bytes) -> bytes:
        block_size = self.cipher_block_size
        if len(input_data) < block_size or (len(input_data) - block_size) % block_size != 0:
            raise ValueError("Invalid ciphertext for PCBC")
        init_vector = input_data[:block_size]
        cipher_blocks = split_into_blocks(input_data[block_size:], block_size)
        if not cipher_blocks:
            return b""
        decrypted_blocks = list(self._task_executor.map(self._decrypt_worker, cipher_blocks))
        prev_cipher = init_vector
        prev_plain = b"\x00" * block_size
        plain_data = []
        for idx, dec_block in enumerate(decrypted_blocks):
            plain_block = xor_bytes(dec_block, xor_bytes(prev_plain, prev_cipher))
            plain_data.append(plain_block)
            prev_plain = plain_block
            prev_cipher = cipher_blocks[idx]
        return remove_padding(b"".join(plain_data), block_size, self.cipher_padding)

    def encrypt_stream(self, input_stream: BinaryIO, output_stream: BinaryIO, buffer_size: int):
        block_size = self.cipher_block_size
        init_vector = self.cipher_iv if self.cipher_iv else secrets.token_bytes(block_size)
        output_stream.write(init_vector)
        prev_plain = b"\x00" * block_size
        prev_cipher = init_vector
        remaining_data = b""
        while True:
            chunk_data = input_stream.read(buffer_size)
            if not chunk_data:
                break
            combined_data = remaining_data + chunk_data
            full_blocks_len = (len(combined_data) // block_size) * block_size
            full_blocks, remaining_data = combined_data[:full_blocks_len], combined_data[full_blocks_len:]
            for plain_block in split_into_blocks(full_blocks, block_size):
                xor_input = xor_bytes(plain_block, xor_bytes(prev_plain, prev_cipher))
                encrypted_block = self.cipher_primitive.encrypt_block(xor_input)
                output_stream.write(encrypted_block)
                prev_plain, prev_cipher = plain_block, encrypted_block
        for plain_block in split_into_blocks(apply_padding(remaining_data, block_size, self.cipher_padding), block_size):
            xor_input = xor_bytes(plain_block, xor_bytes(prev_plain, prev_cipher))
            encrypted_block = self.cipher_primitive.encrypt_block(xor_input)
            output_stream.write(encrypted_block)
            prev_plain, prev_cipher = plain_block, encrypted_block

    def decrypt_stream(self, input_stream: BinaryIO, output_stream: BinaryIO, buffer_size: int):
        block_size = self.cipher_block_size
        init_vector = input_stream.read(block_size)
        if len(init_vector) != block_size:
            raise ValueError("Short ciphertext for PCBC")
        prev_cipher, prev_plain = init_vector, b"\x00" * block_size
        remaining_data = b""
        pending_block = None
        while True:
            chunk_data = input_stream.read(buffer_size)
            if not chunk_data:
                break
            combined_data = remaining_data + chunk_data
            full_blocks_len = (len(combined_data) // block_size) * block_size
            full_blocks, remaining_data = combined_data[:full_blocks_len], combined_data[full_blocks_len:]
            if full_blocks:
                cipher_blocks = split_into_blocks(full_blocks, block_size)
                decrypted = list(self._task_executor.map(self._decrypt_worker, cipher_blocks))
                for idx, dec_block in enumerate(decrypted):
                    plain_block = xor_bytes(dec_block, xor_bytes(prev_plain, prev_cipher))
                    if pending_block is not None:
                        output_stream.write(pending_block)
                    pending_block = plain_block
                    prev_plain, prev_cipher = plain_block, cipher_blocks[idx]
        if remaining_data:
            raise ValueError("Invalid length for PCBC ciphertext")
        if pending_block is not None:
            output_stream.write(remove_padding(pending_block, block_size, self.cipher_padding))