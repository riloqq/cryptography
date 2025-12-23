import secrets
import hashlib
from gmpy2 import mpz
from crypto.primality_tests.miller_rabin_test import MillerRabinTest
from crypto.services.number_service import NumberService


class DiffieHellman:
    def __init__(self, bit_length: int = 256):
        self.bit_length = bit_length
        self.prime_test = MillerRabinTest()
        self.prime_p = mpz(0)
        self.base_g = mpz(0)
        self.priv_key = mpz(0)
        self.pub_key = mpz(0)

    def gen_params(self):
        while True:
            candidate_prime = mpz(secrets.randbits(self.bit_length)) | 1 | (1 << (self.bit_length - 1))
            if self.prime_test.is_prime(candidate_prime):
                self.prime_p = candidate_prime
                break
        self.base_g = mpz(secrets.randbits(self.bit_length - 1)) % self.prime_p
        if self.base_g < 2:
            self.base_g = mpz(2)
        return self.prime_p, self.base_g

    def set_params(self, prime_p: mpz, base_g: mpz):
        self.prime_p = prime_p
        self.base_g = base_g

    def gen_keys(self) -> mpz:
        if self.prime_p == 0:
            raise ValueError("Params not set")
        self.priv_key = mpz(secrets.randbits(self.bit_length - 1))
        self.pub_key = NumberService.mod_pow(self.base_g, self.priv_key, self.prime_p)
        return self.pub_key

    def calc_shared(self, other_pub: mpz) -> mpz:
        return NumberService.mod_pow(other_pub, self.priv_key, self.prime_p)


async def dh_demo():
    print("\nГенерация параметров Диффи-Хеллмана...")
    alice_dh = DiffieHellman(bit_length=256)
    prime_p, base_g = alice_dh.gen_params()
    print(f"Сгенерировано p ({prime_p.bit_length()} бит) и g")

    bob_dh = DiffieHellman()
    bob_dh.set_params(prime_p, base_g)

    alice_pub = alice_dh.gen_keys()
    bob_pub = bob_dh.gen_keys()

    alice_shared = alice_dh.calc_shared(bob_pub)
    bob_shared = bob_dh.calc_shared(alice_pub)

    assert alice_shared == bob_shared
    print("Общий секрет совпадает у Алисы и Боба!")

    shared_bytes = alice_shared.to_bytes((alice_shared.bit_length() + 7) // 8, 'big')
    key_hash = hashlib.sha256(shared_bytes).digest()
    des_key_from_dh = key_hash[:7]  # 56 бит = 7 байт

    print(f"Ключ для DES получен из DH: {des_key_from_dh.hex()}")

    from crypto.cipher_primitives.DES.des_cipher import DES
    from crypto.symmetric_context import SymmetricCipherContext
    from crypto.utility.modes import CipherMode, PaddingMode

    message = b"Secret message encrypted with DH-derived key!"
    ctx = SymmetricCipherContext(
        cipher_primitive=DES(),
        cipher_key=des_key_from_dh,
        cipher_mode=CipherMode.CBC,
        cipher_padding=PaddingMode.PKCS7,
        cipher_iv=b"12345678"
    )

    encrypted = await ctx.encrypt_data(message)
    decrypted = await ctx.decrypt_data(encrypted)

    assert decrypted == message
    print("Шифрование ключом из Diffie-Hellman: УСПЕШНО!")
    print("Протокол Диффи-Хеллмана полностью работает!")