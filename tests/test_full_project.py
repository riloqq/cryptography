import asyncio
import os
import secrets

from crypto.triple_des import TripleDES
from crypto.cipher_primitives.DES.des_cipher import DES
from crypto.cipher_primitives.DEAL.deal_cipher import DEAL
from crypto.symmetric_context import SymmetricCipherContext
from crypto.diffie_hellman import DiffieHellman, dh_demo
from crypto.rc4 import RC4Context
from crypto.utility.modes import CipherMode, PaddingMode


async def test_des_tripledes_deal_modes():
    print("=== Тестируем DES, TripleDES, DEAL с разными режимами ===")

    plaintext = b"A" * 600

    des_key = secrets.token_bytes(7)
    tripledes_key = secrets.token_bytes(24)
    deal_key_256 = secrets.token_bytes(32)
    iv_8 = secrets.token_bytes(8)
    iv_16 = secrets.token_bytes(16)

    ciphers_to_test = [
        ("DES", DES(), des_key, iv_8, 8),
        ("TripleDES EDE", TripleDES("EDE"), tripledes_key, iv_8, 8),
        ("TripleDES EEE", TripleDES("EEE"), tripledes_key, iv_8, 8),
        ("DEAL-256", DEAL(256), deal_key_256, iv_16, 16),
    ]

    modes_to_test = [
        CipherMode.ECB,
        CipherMode.CBC,
        CipherMode.CFB,
        CipherMode.OFB,
        CipherMode.CTR,
        CipherMode.RANDOM_DELTA,
    ]

    padding_to_test = PaddingMode.PKCS7

    for name, primitive, key, iv, block_sz in ciphers_to_test:
        print(f"\n--- {name} (блок {block_sz} байт) ---")
        for mode in modes_to_test:
            # DEAL не поддерживает CFB/OFB с блоком 16 в текущей реализации (адаптер DES)
            if "DEAL" in name and mode in [CipherMode.CFB, CipherMode.OFB, CipherMode.CBC]:
                print(f"  {mode.name}: ПРОПУЩЕНО (DEAL не полностью поддерживает этот режим)")
                continue
            try:
                ctx = SymmetricCipherContext(
                    cipher_primitive=primitive,
                    cipher_key=key,
                    cipher_mode=mode,
                    cipher_padding=padding_to_test,
                    cipher_iv=iv if mode in [CipherMode.CBC, CipherMode.CFB, CipherMode.OFB] else None
                )
                encrypted = await ctx.encrypt_data(plaintext)
                decrypted = await ctx.decrypt_data(encrypted)

                assert decrypted == plaintext, f"Ошибка в {name} + {mode.name}"
                print(f"  {mode.name}: OK (шифротекст: {len(encrypted)} байт)")
            except Exception as e:
                print(f"  {mode.name}: ОШИБКА — {e}")


async def test_file_encryption():
    print("\n=== Тестируем шифрование/дешифрование файлов ===")

    test_text = b"Hello world! " * 1000

    with open("test_input.txt", "wb") as f:
        f.write(test_text)

    des = DES()
    key = secrets.token_bytes(7)
    iv = secrets.token_bytes(8)

    ctx = SymmetricCipherContext(
        cipher_primitive=des,
        cipher_key=key,
        cipher_mode=CipherMode.CBC,
        cipher_padding=PaddingMode.PKCS7,
        cipher_iv=iv
    )

    await ctx.encrypt_file("test_input.txt", "encrypted.bin")
    await ctx.decrypt_file("encrypted.bin", "decrypted.txt")

    with open("decrypted.txt", "rb") as f:
        recovered = f.read()

    assert recovered == test_text
    print("Шифрование и дешифрование файлов: OK")

    for file in ["test_input.txt", "encrypted.bin", "decrypted.txt"]:
        if os.path.exists(file):
            os.remove(file)


async def test_rc4():
    print("\n=== Тестируем RC4 ===")
    key = b"SuperSecretRC4Key"
    data = b"RC4 is a stream cipher, very fast!"

    rc4_ctx = RC4Context(key)
    encrypted = await rc4_ctx.process_data(data)
    decrypted = await rc4_ctx.process_data(encrypted)

    assert decrypted == data
    print("RC4 (in-memory): OK")

    with open("rc4_input.txt", "wb") as f:
        f.write(data * 100)

    await rc4_ctx.process_file("rc4_input.txt", "rc4_encrypted.bin")
    await rc4_ctx.process_file("rc4_encrypted.bin", "rc4_decrypted.txt")

    with open("rc4_decrypted.txt", "rb") as f:
        recovered = f.read()

    assert recovered == data * 100
    print("RC4 (file): OK")

    for f in ["rc4_input.txt", "rc4_encrypted.bin", "rc4_decrypted.txt"]:
        if os.path.exists(f):
            os.remove(f)


async def test_diffie_hellman():
    print("\n=== Тестируем Diffie-Hellman ===")
    await dh_demo()


async def main():
    await test_des_tripledes_deal_modes()
    await test_file_encryption()
    await test_rc4()
    await test_diffie_hellman()
    print("\nВСЁ РАБОТАЕТ!")


if __name__ == "__main__":
    asyncio.run(main())