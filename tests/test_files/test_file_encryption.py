import asyncio
import os
import secrets

from crypto.cipher_primitives.DES.des_cipher import DES
from crypto.triple_des import TripleDES
from crypto.cipher_primitives.DEAL.deal_cipher import DEAL
from crypto.symmetric_context import SymmetricCipherContext
from crypto.utility.modes import CipherMode, PaddingMode

TEST_DIR = "test_files"

PHOTO_PATH = os.path.join(TEST_DIR, "photo_2025-08-07_23-15-46.jpg")


async def test_file_with_cipher(primitive, key, mode, iv, name):
    ctx = SymmetricCipherContext(
        cipher_primitive=primitive,
        cipher_key=key,
        cipher_mode=mode,
        cipher_padding=PaddingMode.PKCS7,
        cipher_iv=iv
    )

    test_files = [
        "small_text.txt",
        "large_text.txt",
        "binary_data.bin",
        "empty_file.txt",
        "photo_2025-08-07_23-15-46.jpg",
    ]

    for filename in test_files:
        input_path = os.path.join(TEST_DIR, filename)

        if not os.path.exists(input_path):
            print(f"⚠️  Файл не найден: {input_path} — пропускаю")
            continue

        enc_path = input_path + f".{name.lower()}.enc"
        dec_path = input_path + f".{name.lower()}.dec"

        print(f"\n{name} | {mode.name} | файл: {filename}")
        print(f"  Оригинал: {input_path}")
        print(f"  Зашифрованный: {enc_path}")
        print(f"  Расшифрованный: {dec_path}")

        await ctx.encrypt_file(input_path, enc_path)
        print("  → Зашифрован")

        await ctx.decrypt_file(enc_path, dec_path)
        print("  → Расшифрован")

        with open(input_path, "rb") as orig, open(dec_path, "rb") as dec:
            assert orig.read() == dec.read(), f"Ошибка восстановления {filename}!"
        print("  ✓ Файл успешно восстановлен (байты совпадают)")

    print(f"\n{name} прошёл все тесты. Зашифрованные и расшифрованные файлы сохранены для проверки!\n")


async def main():
    print("=== Тестирование шифрования/дешифрования файлов (файлы НЕ удаляются) ===\n")

    os.makedirs(TEST_DIR, exist_ok=True)

    if not os.path.exists(PHOTO_PATH):
        raise FileNotFoundError(
            f"Фото не найдено по пути: {PHOTO_PATH}\n"
            f"Положи файл 'photo_2025-08-07_23-15-46.jpg' в папку '{TEST_DIR}'"
        )

    key_des = secrets.token_bytes(7)
    key_tdes = secrets.token_bytes(24)
    key_deal = secrets.token_bytes(32)
    iv = secrets.token_bytes(8)

    await test_file_with_cipher(DES(), key_des, CipherMode.CBC, iv, "DES")
    await test_file_with_cipher(TripleDES("EDE"), key_tdes, CipherMode.CBC, iv, "TripleDES")
    await test_file_with_cipher(DEAL(256), key_deal, CipherMode.CTR, None, "DEAL")

    print("ВСЕ ТЕСТЫ ЗАВЕРШЕНЫ! Зашифрованные (*.enc) и расшифрованные (*.dec) файлы остались в папке test_files.")
    print("Открой .dec версию фото — она должна быть идентична оригиналу!")

if __name__ == "__main__":
    asyncio.run(main())