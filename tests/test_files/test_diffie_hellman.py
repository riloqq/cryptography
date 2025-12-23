import asyncio
import secrets

from crypto.diffie_hellman import DiffieHellman
from crypto.cipher_primitives.DES.des_cipher import DES
from crypto.symmetric_context import SymmetricCipherContext
from crypto.utility.modes import CipherMode, PaddingMode


async def main():
    print("=== Тестирование протокола Диффи-Хеллмана ===\n")

    alice = DiffieHellman(bit_length=256)
    p, g = alice.gen_params()
    print(f"Параметры сгенерированы: p ({p.bit_length()} бит), g = {g}")

    bob = DiffieHellman()
    bob.set_params(p, g)

    alice_pub = alice.gen_keys()
    bob_pub = bob.gen_keys()
    print(f"Публичный ключ Алисы: {alice_pub}")
    print(f"Публичный ключ Боба: {bob_pub}")

    alice_secret = alice.calc_shared(bob_pub)
    bob_secret = bob.calc_shared(alice_pub)

    assert alice_secret == bob_secret
    print(f"Общий секрет совпадает! Длина: {alice_secret.bit_length()} бит")

    import hashlib
    secret_bytes = alice_secret.to_bytes((alice_secret.bit_length() + 7) // 8, 'big')
    des_key = hashlib.sha256(secret_bytes).digest()[:7]

    print(f"Ключ для DES (7 байт): {des_key.hex()}")

    message = b"Message encrypted with Diffie-Hellman derived key!"
    ctx = SymmetricCipherContext(
        cipher_primitive=DES(),
        cipher_key=des_key,
        cipher_mode=CipherMode.CBC,
        cipher_padding=PaddingMode.PKCS7,
        cipher_iv=secrets.token_bytes(8)
    )

    encrypted = await ctx.encrypt_data(message)
    decrypted = await ctx.decrypt_data(encrypted)

    assert decrypted == message
    print(f"Оригинал: {message}")
    print(f"Зашифровано: {encrypted.hex()}")
    print(f"Расшифровано: {decrypted}")
    print("Шифрование ключом из DH прошло успешно!")

    print("\nПротокол Диффи-Хеллмана полностью работает!")

if __name__ == "__main__":
    asyncio.run(main())