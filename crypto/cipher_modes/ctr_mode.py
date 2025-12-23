import secrets
from typing import BinaryIO, Tuple
from .base_mode import BaseCipherMode
from crypto.utility.utility import split_into_blocks, xor_bytes

class CTRMode(BaseCipherMode):
    def _ctr_worker(self, args: Tuple[bytes, int]):
        nonce_val, counter_val = args
        counter_bytes = counter_val.to_bytes(self.cipher_block_size // 2, "big")
        return self.cipher_primitive.encrypt_block(nonce_val + counter_bytes)

    def encrypt_data(self, input_data: bytes) -> bytes:
        block_size = self.cipher_block_size
        nonce_val = self.cipher_iv if self.cipher_iv else secrets.token_bytes(block_size // 2)
        full_count = len(input_data) // block_size
        full_data = input_data[:full_count * block_size]
        remaining_tail = input_data[full_count * block_size:]
        data_blocks = split_into_blocks(full_data, block_size)
        counter_args = [(nonce_val, i) for i in range(len(data_blocks))]
        stream_blocks = list(self._task_executor.map(self._ctr_worker, counter_args))
        output_data = [nonce_val] + [xor_bytes(block, stream) for block, stream in zip(data_blocks, stream_blocks)]
        if remaining_tail:
            counter_bytes = len(data_blocks).to_bytes(block_size // 2, "big")
            stream_tail = self.cipher_primitive.encrypt_block(nonce_val + counter_bytes)
            output_data.append(xor_bytes(remaining_tail, stream_tail[:len(remaining_tail)]))
        return b"".join(output_data)

    def decrypt_data(self, input_data: bytes) -> bytes:
        block_size = self.cipher_block_size
        if len(input_data) < block_size // 2:
            raise ValueError("Short ciphertext for CTR")
        nonce_val = input_data[:block_size // 2]
        cipher_data = input_data[block_size // 2:]
        full_count = len(cipher_data) // block_size
        full_data = cipher_data[:full_count * block_size]
        remaining_tail = cipher_data[full_count * block_size:]
        data_blocks = split_into_blocks(full_data, block_size)
        counter_args = [(nonce_val, i) for i in range(len(data_blocks))]
        stream_blocks = list(self._task_executor.map(self._ctr_worker, counter_args))
        output_data = [xor_bytes(block, stream) for block, stream in zip(data_blocks, stream_blocks)]
        if remaining_tail:
            counter_bytes = len(data_blocks).to_bytes(block_size // 2, "big")
            stream_tail = self.cipher_primitive.encrypt_block(nonce_val + counter_bytes)
            output_data.append(xor_bytes(remaining_tail, stream_tail[:len(remaining_tail)]))
        return b"".join(output_data)

    def encrypt_stream(self, input_stream: BinaryIO, output_stream: BinaryIO, buffer_size: int):
        block_size = self.cipher_block_size
        nonce_val = self.cipher_iv if self.cipher_iv else secrets.token_bytes(block_size // 2)
        output_stream.write(nonce_val)
        counter_val = 0
        remaining_data = b""
        while True:
            chunk_data = input_stream.read(buffer_size)
            if not chunk_data:
                break
            combined_data = remaining_data + chunk_data
            full_blocks_len = (len(combined_data) // block_size) * block_size
            full_blocks, remaining_data = combined_data[:full_blocks_len], combined_data[full_blocks_len:]
            if full_blocks:
                data_blocks = split_into_blocks(full_blocks, block_size)
                counter_args = [(nonce_val, counter_val + i) for i in range(len(data_blocks))]
                stream_blocks = list(self._task_executor.map(self._ctr_worker, counter_args))
                for block, stream in zip(data_blocks, stream_blocks):
                    output_stream.write(xor_bytes(block, stream))
                counter_val += len(data_blocks)
        if remaining_data:
            counter_bytes = counter_val.to_bytes(block_size // 2, "big")
            stream_tail = self.cipher_primitive.encrypt_block(nonce_val + counter_bytes)
            output_stream.write(xor_bytes(remaining_data, stream_tail[:len(remaining_data)]))

    def decrypt_stream(self, input_stream: BinaryIO, output_stream: BinaryIO, buffer_size: int):
        block_size = self.cipher_block_size
        nonce_val = input_stream.read(block_size // 2)
        if len(nonce_val) != block_size // 2:
            raise ValueError("Short ciphertext for CTR")
        counter_val = 0
        remaining_data = b""
        while True:
            chunk_data = input_stream.read(buffer_size)
            if not chunk_data:
                break
            combined_data = remaining_data + chunk_data
            full_blocks_len = (len(combined_data) // block_size) * block_size
            full_blocks, remaining_data = combined_data[:full_blocks_len], combined_data[full_blocks_len:]
            if full_blocks:
                data_blocks = split_into_blocks(full_blocks, block_size)
                counter_args = [(nonce_val, counter_val + i) for i in range(len(data_blocks))]
                stream_blocks = list(self._task_executor.map(self._ctr_worker, counter_args))
                for block, stream in zip(data_blocks, stream_blocks):
                    output_stream.write(xor_bytes(block, stream))
                counter_val += len(data_blocks)
        if remaining_data:
            counter_bytes = counter_val.to_bytes(block_size // 2, "big")
            stream_tail = self.cipher_primitive.encrypt_block(nonce_val + counter_bytes)
            output_stream.write(xor_bytes(remaining_data, stream_tail[:len(remaining_data)]))