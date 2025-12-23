import secrets
from typing import BinaryIO
from .base_mode import BaseCipherMode
from crypto.utility.utility import apply_padding, remove_padding, split_into_blocks

class ECBMode(BaseCipherMode):
    def _encrypt_worker(self, data_block: bytes):
        return self.cipher_primitive.encrypt_block(data_block)

    def _decrypt_worker(self, data_block: bytes):
        return self.cipher_primitive.decrypt_block(data_block)

    def encrypt_data(self, input_data: bytes) -> bytes:
        padded_data = apply_padding(input_data, self.cipher_block_size, self.cipher_padding)
        data_blocks = split_into_blocks(padded_data, self.cipher_block_size)
        encrypted_blocks = list(self._task_executor.map(self._encrypt_worker, data_blocks))
        return b"".join(encrypted_blocks)

    def decrypt_data(self, input_data: bytes) -> bytes:
        if len(input_data) % self.cipher_block_size != 0:
            raise ValueError("Invalid length for ECB ciphertext")
        data_blocks = split_into_blocks(input_data, self.cipher_block_size)
        decrypted_blocks = list(self._task_executor.map(self._decrypt_worker, data_blocks))
        return remove_padding(b"".join(decrypted_blocks), self.cipher_block_size, self.cipher_padding)

    def encrypt_stream(self, input_stream: BinaryIO, output_stream: BinaryIO, buffer_size: int):
        remaining_data = b""
        while True:
            chunk_data = input_stream.read(buffer_size)
            if not chunk_data:
                break
            combined_data = remaining_data + chunk_data
            full_blocks_len = (len(combined_data) // self.cipher_block_size) * self.cipher_block_size
            full_blocks, remaining_data = combined_data[:full_blocks_len], combined_data[full_blocks_len:]
            if full_blocks:
                data_blocks = split_into_blocks(full_blocks, self.cipher_block_size)
                results = list(self._task_executor.map(self._encrypt_worker, data_blocks))
                output_stream.write(b"".join(results))
        padded_remaining = apply_padding(remaining_data, self.cipher_block_size, self.cipher_padding)
        data_blocks = split_into_blocks(padded_remaining, self.cipher_block_size)
        results = list(self._task_executor.map(self._encrypt_worker, data_blocks))
        output_stream.write(b"".join(results))

    def decrypt_stream(self, input_stream: BinaryIO, output_stream: BinaryIO, buffer_size: int):
        remaining_data = b""
        pending_block = None
        while True:
            chunk_data = input_stream.read(buffer_size)
            if not chunk_data:
                break
            combined_data = remaining_data + chunk_data
            full_blocks_len = (len(combined_data) // self.cipher_block_size) * self.cipher_block_size
            full_blocks, remaining_data = combined_data[:full_blocks_len], combined_data[full_blocks_len:]
            if full_blocks:
                data_blocks = split_into_blocks(full_blocks, self.cipher_block_size)
                results = list(self._task_executor.map(self._decrypt_worker, data_blocks))
                for block in results:
                    if pending_block is not None:
                        output_stream.write(pending_block)
                    pending_block = block
        if remaining_data:
            raise ValueError("Invalid length for ECB ciphertext")
        if pending_block is not None:
            output_stream.write(remove_padding(pending_block, self.cipher_block_size, self.cipher_padding))