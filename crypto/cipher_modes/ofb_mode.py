import secrets
from typing import BinaryIO
from .base_mode import BaseCipherMode
from crypto.utility.utility import split_into_blocks, xor_bytes

class OFBMode(BaseCipherMode):
    def encrypt_data(self, input_data: bytes) -> bytes:
        block_size = self.cipher_block_size
        init_vector = self.cipher_iv if self.cipher_iv else secrets.token_bytes(block_size)
        full_count = len(input_data) // block_size
        full_data = input_data[:full_count * block_size]
        remaining_tail = input_data[full_count * block_size:]
        prev_stream = init_vector
        output_data = [init_vector]
        for plain_block in split_into_blocks(full_data, block_size):
            prev_stream = self.cipher_primitive.encrypt_block(prev_stream)
            output_data.append(xor_bytes(plain_block, prev_stream))
        if remaining_tail:
            prev_stream = self.cipher_primitive.encrypt_block(prev_stream)
            output_data.append(xor_bytes(remaining_tail, prev_stream[:len(remaining_tail)]))
        return b"".join(output_data)

    def decrypt_data(self, input_data: bytes) -> bytes:
        block_size = self.cipher_block_size
        if len(input_data) < block_size:
            raise ValueError("Short ciphertext for OFB")
        init_vector = input_data[:block_size]
        cipher_data = input_data[block_size:]
        full_count = len(cipher_data) // block_size
        full_data = cipher_data[:full_count * block_size]
        remaining_tail = cipher_data[full_count * block_size:]
        prev_stream = init_vector
        output_data = []
        for cipher_block in split_into_blocks(full_data, block_size):
            prev_stream = self.cipher_primitive.encrypt_block(prev_stream)
            output_data.append(xor_bytes(cipher_block, prev_stream))
        if remaining_tail:
            prev_stream = self.cipher_primitive.encrypt_block(prev_stream)
            output_data.append(xor_bytes(remaining_tail, prev_stream[:len(remaining_tail)]))
        return b"".join(output_data)

    def encrypt_stream(self, input_stream: BinaryIO, output_stream: BinaryIO, buffer_size: int):
        block_size = self.cipher_block_size
        init_vector = self.cipher_iv if self.cipher_iv else secrets.token_bytes(block_size)
        output_stream.write(init_vector)
        prev_stream = init_vector
        remaining_data = b""
        while True:
            chunk_data = input_stream.read(buffer_size)
            if not chunk_data:
                break
            combined_data = remaining_data + chunk_data
            full_blocks_len = (len(combined_data) // block_size) * block_size
            full_blocks, remaining_data = combined_data[:full_blocks_len], combined_data[full_blocks_len:]
            for plain_block in split_into_blocks(full_blocks, block_size):
                prev_stream = self.cipher_primitive.encrypt_block(prev_stream)
                output_stream.write(xor_bytes(plain_block, prev_stream))
        if remaining_data:
            prev_stream = self.cipher_primitive.encrypt_block(prev_stream)
            output_stream.write(xor_bytes(remaining_data, prev_stream[:len(remaining_data)]))

    def decrypt_stream(self, input_stream: BinaryIO, output_stream: BinaryIO, buffer_size: int):
        block_size = self.cipher_block_size
        init_vector = input_stream.read(block_size)
        if len(init_vector) != block_size:
            raise ValueError("Short ciphertext for OFB")
        prev_stream = init_vector
        remaining_data = b""
        while True:
            chunk_data = input_stream.read(buffer_size)
            if not chunk_data:
                break
            combined_data = remaining_data + chunk_data
            full_blocks_len = (len(combined_data) // block_size) * block_size
            full_blocks, remaining_data = combined_data[:full_blocks_len], combined_data[full_blocks_len:]
            for cipher_block in split_into_blocks(full_blocks, block_size):
                prev_stream = self.cipher_primitive.encrypt_block(prev_stream)
                output_stream.write(xor_bytes(cipher_block, prev_stream))
        if remaining_data:
            prev_stream = self.cipher_primitive.encrypt_block(prev_stream)
            output_stream.write(xor_bytes(remaining_data, prev_stream[:len(remaining_data)]))