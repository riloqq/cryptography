import asyncio
import os

from crypto.rc4 import RC4Context

TEST_DIR = "test_files"

PHOTO_PATH = os.path.join(TEST_DIR, "photo_2025-08-07_23-15-46.jpg")


async def main():
    print("=== Тестирование RC4 на всех файлах (файлы НЕ удаляются) ===\n")

    if not os.path.exists(PHOTO_PATH):
        raise FileNotFoundError(f"Фото не найдено: {PHOTO_PATH}\nПоложи его в папку {TEST_DIR}")

    key = b"MySuperSecretRC4Key2025"
    rc4_ctx = RC4Context(key)

    for filename in os.listdir(TEST_DIR):
        input_path = os.path.join(TEST_DIR, filename)

        enc_path = input_path + ".rc4.enc"
        dec_path = input_path + ".rc4.dec"

        print(f"RC4 | файл: {filename}")
        print(f"  Оригинал: {input_path}")
        print(f"  Зашифрованный: {enc_path}")
        print(f"  Расшифрованный: {dec_path}")

        await rc4_ctx.process_file(input_path, enc_path)
        print("  → Зашифрован")

        await rc4_ctx.process_file(enc_path, dec_path)
        print("  → Расшифрован")

        with open(input_path, "rb") as orig, open(dec_path, "rb") as dec:
            assert orig.read() == dec.read(), f"Ошибка восстановления {filename}!"
        print("  ✓ Файл успешно восстановлен\n")

    print("RC4 прошёл все тесты! Зашифрованные (*.rc4.enc) и расшифрованные (*.rc4.dec) файлы сохранены.")
    print("Открой .rc4.dec версию фото — оно должно быть как оригинал!")

if __name__ == "__main__":
    asyncio.run(main())