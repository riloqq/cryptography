from abc import ABC, abstractmethod
from typing import BinaryIO, Optional
from concurrent.futures import ThreadPoolExecutor

class BaseCipherMode(ABC):
    def __init__(self, cipher_primitive, cipher_key: bytes, cipher_block_size: int, cipher_padding, cipher_iv: Optional[bytes] = None, task_executor: ThreadPoolExecutor = None):
        self.cipher_primitive = cipher_primitive
        self.cipher_key = cipher_key
        self.cipher_block_size = cipher_block_size
        self.cipher_padding = cipher_padding
        self.cipher_iv = cipher_iv
        self._task_executor = task_executor or ThreadPoolExecutor(max_workers=6)

    @abstractmethod
    def encrypt_data(self, input_data: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt_data(self, input_data: bytes) -> bytes:
        pass

    @abstractmethod
    def encrypt_stream(self, input_stream: BinaryIO, output_stream: BinaryIO, buffer_size: int):
        pass

    @abstractmethod
    def decrypt_stream(self, input_stream: BinaryIO, output_stream: BinaryIO, buffer_size: int):
        pass