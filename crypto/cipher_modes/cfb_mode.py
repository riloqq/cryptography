import secrets
from typing import BinaryIO
from .base_mode import BaseCipherMode
from crypto.utility.utility import split_into_blocks, xor_bytes

class CFBMode(BaseCipherMode):
    def _encrypt_worker(self, data_block: bytes):
        return self.cipher_primitive.encrypt_block(data_block)

    def encrypt_data(self, input_data: bytes) -> bytes:
        block_size = self.cipher_block_size
        init_vector = self.cipher_iv if self.cipher_iv else secrets.token_bytes(block_size)
        full_count = len(input_data) // block_size
        full_data = input_data[:full_count * block_size]
        remaining_tail = input_data[full_count * block_size:]
        prev_cipher = init_vector
        output_data = [init_vector]
        for plain_block in split_into_blocks(full_data, block_size):
            stream = self.cipher_primitive.encrypt_block(prev_cipher)
            cipher_block = xor_bytes(plain_block, stream)
            output_data.append(cipher_block)
            prev_cipher = cipher_block
        if remaining_tail:
            stream = self.cipher_primitive.encrypt_block(prev_cipher)
            cipher_tail = xor_bytes(remaining_tail, stream[:len(remaining_tail)])
            output_data.append(cipher_tail)
        return b"".join(output_data)

    def decrypt_data(self, input_data: bytes) -> bytes:
        block_size = self.cipher_block_size
        if len(input_data) < block_size:
            raise ValueError("Short ciphertext for CFB")
        init_vector = input_data[:block_size]
        cipher_data = input_data[block_size:]
        if not cipher_data:
            return b""
        full_count = len(cipher_data) // block_size
        full_data = cipher_data[:full_count * block_size]
        remaining_tail = cipher_data[full_count * block_size:]
        output_data = []
        if full_data:
            cipher_blocks = split_into_blocks(full_data, block_size)
            inputs = [init_vector] + cipher_blocks[:-1]
            streams = list(self._task_executor.map(self._encrypt_worker, inputs))
            output_data = [xor_bytes(c_block, stream) for c_block, stream in zip(cipher_blocks, streams)]
        if remaining_tail:
            prev_cipher = cipher_blocks[-1] if full_data else init_vector
            stream = self.cipher_primitive.encrypt_block(prev_cipher)
            output_data.append(xor_bytes(remaining_tail, stream[:len(remaining_tail)]))
        return b"".join(output_data)

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
                stream = self.cipher_primitive.encrypt_block(prev_cipher)
                cipher_block = xor_bytes(plain_block, stream)
                output_stream.write(cipher_block)
                prev_cipher = cipher_block
        if remaining_data:
            stream = self.cipher_primitive.encrypt_block(prev_cipher)
            output_stream.write(xor_bytes(remaining_data, stream[:len(remaining_data)]))

    def decrypt_stream(self, input_stream: BinaryIO, output_stream: BinaryIO, buffer_size: int):
        block_size = self.cipher_block_size
        init_vector = input_stream.read(block_size)
        if len(init_vector) != block_size:
            raise ValueError("Short ciphertext for CFB")
        remaining_data = b""
        prev_cipher = init_vector
        while True:
            chunk_data = input_stream.read(buffer_size)
            if not chunk_data:
                break
            combined_data = remaining_data + chunk_data
            full_blocks_len = (len(combined_data) // block_size) * block_size
            full_blocks, remaining_data = combined_data[:full_blocks_len], combined_data[full_blocks_len:]
            if full_blocks:
                cipher_blocks = split_into_blocks(full_blocks, block_size)
                inputs = [prev_cipher] + cipher_blocks[:-1]
                streams = list(self._task_executor.map(self._encrypt_worker, inputs))
                plain_blocks = [xor_bytes(c_block, stream) for c_block, stream in zip(cipher_blocks, streams)]
                output_stream.write(b"".join(plain_blocks))
                prev_cipher = cipher_blocks[-1]
        if remaining_data:
            stream = self.cipher_primitive.encrypt_block(prev_cipher)
            output_stream.write(xor_bytes(remaining_data, stream[:len(remaining_data)]))