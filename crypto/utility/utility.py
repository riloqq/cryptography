import secrets
from crypto.utility.modes import PaddingMode


def apply_padding(input_data: bytes, block_size: int, padding_mode: PaddingMode) -> bytes:
    pad_len = block_size - (len(input_data) % block_size)
    if pad_len == block_size:
        pad_len = 0
    if pad_len == 0:
        return input_data
    if padding_mode == PaddingMode.ZEROS:
        return input_data + b"\x00" * pad_len
    if padding_mode == PaddingMode.PKCS7:
        return input_data + bytes([pad_len]) * pad_len
    if padding_mode == PaddingMode.ANSI_X923:
        return input_data + b"\x00" * (pad_len - 1) + bytes([pad_len])
    if padding_mode == PaddingMode.ISO_10126:
        return input_data + secrets.token_bytes(pad_len - 1) + bytes([pad_len])
    raise ValueError("Unknown padding")


def remove_padding(input_data: bytes, block_size: int, padding_mode: PaddingMode) -> bytes:
    if len(input_data) == 0:
        return input_data
    if padding_mode == PaddingMode.ZEROS:
        return input_data.rstrip(b"\x00")

    if padding_mode in [PaddingMode.PKCS7, PaddingMode.ANSI_X923, PaddingMode.ISO_10126]:
        if len(input_data) < block_size:
            return input_data

        pad_len = input_data[-1]
        if pad_len == 0 or pad_len > block_size:
            return input_data

        if padding_mode == PaddingMode.PKCS7:
            expected = bytes([pad_len]) * pad_len
            if input_data[-pad_len:] == expected:
                return input_data[:-pad_len]
            else:
                return input_data

        if padding_mode == PaddingMode.ANSI_X923:
            if input_data[-pad_len:-1] == b"\x00" * (pad_len - 1) and input_data[-1] == pad_len:
                return input_data[:-pad_len]
            else:
                return input_data

        if padding_mode == PaddingMode.ISO_10126:
            return input_data[:-pad_len]

    return input_data


def xor_bytes(bytes_a: bytes, bytes_b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(bytes_a, bytes_b))


def split_into_blocks(input_data: bytes, block_size: int) -> list[bytes]:
    return [input_data[i:i + block_size] for i in range(0, len(input_data), block_size)]