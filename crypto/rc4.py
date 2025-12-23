import asyncio
from concurrent.futures import ThreadPoolExecutor


class RC4:
    def __init__(self, rc4_key: bytes):
        self.rc4_key = rc4_key
        self._init_state()

    def _init_state(self):
        key_length = len(self.rc4_key)
        self.state_arr = list(range(256))
        j_val = 0
        for i_val in range(256):
            j_val = (j_val + self.state_arr[i_val] + self.rc4_key[i_val % key_length]) % 256
            self.state_arr[i_val], self.state_arr[j_val] = self.state_arr[j_val], self.state_arr[i_val]
        self.i_val = self.j_val = 0

    def _gen_byte(self):
        self.i_val = (self.i_val + 1) % 256
        self.j_val = (self.j_val + self.state_arr[self.i_val]) % 256
        self.state_arr[self.i_val], self.state_arr[self.j_val] = self.state_arr[self.j_val], self.state_arr[self.i_val]
        k_byte = self.state_arr[(self.state_arr[self.i_val] + self.state_arr[self.j_val]) % 256]
        return k_byte

    def process_data(self, input_data: bytes) -> bytes:
        return bytes(b ^ self._gen_byte() for b in input_data)


class RC4Context:
    def __init__(self, rc4_key: bytes, max_threads: int = 4):
        self.rc4_key = rc4_key
        self._thread_pool = ThreadPoolExecutor(max_workers=max_threads)

    async def process_data(self, input_data: bytes) -> bytes:
        event_loop = asyncio.get_running_loop()
        return await event_loop.run_in_executor(self._thread_pool, lambda: RC4(self.rc4_key).process_data(input_data))

    async def process_file(self, in_path: str, out_path: str, buffer_size: int = 1024 * 1024):
        event_loop = asyncio.get_running_loop()
        await event_loop.run_in_executor(self._thread_pool, self._process_file_impl, in_path, out_path, buffer_size)

    def _process_file_impl(self, in_path: str, out_path: str, buffer_size: int):
        rc4_inst = RC4(self.rc4_key)
        with open(in_path, "rb") as in_file, open(out_path, "wb") as out_file:
            while True:
                chunk_data = in_file.read(buffer_size)
                if not chunk_data:
                    break
                out_file.write(rc4_inst.process_data(chunk_data))