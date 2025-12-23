import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
from crypto.utility.modes import CipherMode, PaddingMode
from crypto.cipher_modes.ecb_mode import ECBMode
from crypto.cipher_modes.cbc_mode import CBCMode
from crypto.cipher_modes.pcbc_mode import PCBCMode
from crypto.cipher_modes.cfb_mode import CFBMode
from crypto.cipher_modes.ofb_mode import OFBMode
from crypto.cipher_modes.ctr_mode import CTRMode
from crypto.cipher_modes.random_delta_mode import RandomDeltaMode


class SymmetricCipherContext:
    _MODE_MAP = {
        CipherMode.ECB: ECBMode,
        CipherMode.CBC: CBCMode,
        CipherMode.PCBC: PCBCMode,
        CipherMode.CFB: CFBMode,
        CipherMode.OFB: OFBMode,
        CipherMode.CTR: CTRMode,
        CipherMode.RANDOM_DELTA: RandomDeltaMode,
    }

    def __init__(self, cipher_primitive, cipher_key: bytes, cipher_mode: CipherMode = CipherMode.ECB,
                 cipher_padding: PaddingMode = PaddingMode.PKCS7, cipher_iv: Optional[bytes] = None,
                 max_threads: int = 6):
        self.cipher_primitive = cipher_primitive
        self.cipher_key = cipher_key
        self.cipher_mode = cipher_mode
        self.cipher_padding = cipher_padding
        self.cipher_iv = cipher_iv
        self.block_size = getattr(cipher_primitive, "block_size", 8)
        if hasattr(cipher_primitive, "setup_keys"):
            cipher_primitive.setup_keys(cipher_key)
        self._thread_pool = ThreadPoolExecutor(max_workers=max_threads)
        mode_class = self._MODE_MAP.get(cipher_mode)
        if not mode_class:
            raise ValueError("Mode not supported")
        self._mode_handler = mode_class(cipher_primitive, cipher_key, self.block_size, cipher_padding, cipher_iv, self._thread_pool)

    async def encrypt_data(self, input_data: bytes) -> bytes:
        event_loop = asyncio.get_running_loop()
        return await event_loop.run_in_executor(self._thread_pool, self._mode_handler.encrypt_data, input_data)

    async def decrypt_data(self, input_data: bytes) -> bytes:
        event_loop = asyncio.get_running_loop()
        return await event_loop.run_in_executor(self._thread_pool, self._mode_handler.decrypt_data, input_data)

    async def encrypt_file(self, in_path: str, out_path: str, buffer_size: int = 1024 * 1024):
        event_loop = asyncio.get_running_loop()
        await event_loop.run_in_executor(self._thread_pool, self._encrypt_file_impl, in_path, out_path, buffer_size)

    def _encrypt_file_impl(self, in_path: str, out_path: str, buffer_size: int):
        with open(in_path, "rb") as in_file, open(out_path, "wb") as out_file:
            self._mode_handler.encrypt_stream(in_file, out_file, buffer_size)

    async def decrypt_file(self, in_path: str, out_path: str, buffer_size: int = 1024 * 1024):
        event_loop = asyncio.get_running_loop()
        await event_loop.run_in_executor(self._thread_pool, self._decrypt_file_impl, in_path, out_path, buffer_size)

    def _decrypt_file_impl(self, in_path: str, out_path: str, buffer_size: int):
        with open(in_path, "rb") as in_file, open(out_path, "wb") as out_file:
            self._mode_handler.decrypt_stream(in_file, out_file, buffer_size)