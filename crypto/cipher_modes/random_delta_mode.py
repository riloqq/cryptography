import secrets
from typing import BinaryIO
from .base_mode import BaseCipherMode
from crypto.utility.utility import apply_padding, remove_padding, split_into_blocks, xor_bytes

class RandomDeltaMode(BaseCipherMode):
    def _decrypt_worker(self, data_block: bytes):
        return self.cipher_primitive.decrypt_block(data_block)

    def encrypt_data(self, input_data: bytes) -> bytes:
        block_size = self.cipher_block_size
        padded_data = apply_padding(input_data, block_size, self.cipher_padding)
        init_vector = self.cipher_iv if self.cipher_iv else secrets.token_bytes(block_size)
        prev_cipher = init_vector
        output_parts = [init_vector]
        for plain_block in split_into_blocks(padded_data, block_size):
            delta_val = secrets.token_bytes(block_size)
            xor_out = self.cipher_primitive.encrypt_block(xor_bytes(plain_block, prev_cipher))
            cipher_block = xor_bytes(xor_out, delta_val)
            output_parts.extend([delta_val, cipher_block])
            prev_cipher = cipher_block
        return b"".join(output_parts)

    def decrypt_data(self, input_data: bytes) -> bytes:
        block_size = self.cipher_block_size
        if len(input_data) < block_size:
            raise ValueError("Short ciphertext for Random Delta")
        init_vector = input_data[:block_size]
        cipher_data = input_data[block_size:]
        if len(cipher_data) % (block_size * 2) != 0:
            raise ValueError("Invalid length for Random Delta ciphertext")
        combined_blocks = split_into_blocks(cipher_data, block_size * 2)
        pairs = [(c[:block_size], c[block_size:]) for c in combined_blocks]
        xor_blocks = [xor_bytes(c_block, delta) for delta, c_block in pairs]
        decrypted_xor = list(self._task_executor.map(self._decrypt_worker, xor_blocks))
        prev_cipher = init_vector
        plain_parts = []
        for dec_xor, pair in zip(decrypted_xor, pairs):
            plain_block = xor_bytes(dec_xor, prev_cipher)
            plain_parts.append(plain_block)
            prev_cipher = pair[1]
        return remove_padding(b"".join(plain_parts), block_size, self.cipher_padding)

    def encrypt_stream(self, input_stream: BinaryIO, output_stream: BinaryIO, buffer_size: int):
        block_size = self.cipher_block_size
        init_vector = self.cipher_iv if self.cipher_iv else secrets.token_bytes(block_size)
        output_stream.write(init_vector)
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
                delta_val = secrets.token_bytes(block_size)
                xor_out = self.cipher_primitive.encrypt_block(xor_bytes(plain_block, prev_cipher))
                cipher_block = xor_bytes(xor_out, delta_val)
                output_stream.write(delta_val)
                output_stream.write(cipher_block)
                prev_cipher = cipher_block
        for plain_block in split_into_blocks(apply_padding(remaining_data, block_size, self.cipher_padding), block_size):
            delta_val = secrets.token_bytes(block_size)
            xor_out = self.cipher_primitive.encrypt_block(xor_bytes(plain_block, prev_cipher))
            cipher_block = xor_bytes(xor_out, delta_val)
            output_stream.write(delta_val)
            output_stream.write(cipher_block)
            prev_cipher = cipher_block

    def decrypt_stream(self, input_stream: BinaryIO, output_stream: BinaryIO, buffer_size: int):
        block_size = self.cipher_block_size
        init_vector = input_stream.read(block_size)
        if len(init_vector) != block_size:
            raise ValueError("Short ciphertext for Random Delta")
        prev_cipher = init_vector
        remaining_data = b""
        pending_block = None
        while True:
            chunk_data = input_stream.read(buffer_size)
            if not chunk_data:
                break
            combined_data = remaining_data + chunk_data
            full_blocks_len = (len(combined_data) // (block_size * 2)) * (block_size * 2)
            full_blocks, remaining_data = combined_data[:full_blocks_len], combined_data[full_blocks_len:]
            if full_blocks:
                pairs = [(full_blocks[i:i+block_size], full_blocks[i+block_size:i+block_size*2]) for i in range(0, len(full_blocks), block_size*2)]
                xor_blocks = [xor_bytes(c_block, delta) for delta, c_block in pairs]
                decrypted = list(self._task_executor.map(self._decrypt_worker, xor_blocks))
                for idx, dec_xor in enumerate(decrypted):
                    plain_block = xor_bytes(dec_xor, prev_cipher)
                    if pending_block is not None:
                        output_stream.write(pending_block)
                    pending_block = plain_block
                    prev_cipher = pairs[idx][1]
        if remaining_data:
            raise ValueError("Invalid length for Random Delta ciphertext")
        if pending_block is not None:
            output_stream.write(remove_padding(pending_block, block_size, self.cipher_padding))