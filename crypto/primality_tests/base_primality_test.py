import secrets
from abc import ABC, abstractmethod
from gmpy2 import mpz

class BasePrimalityTest(ABC):
    def is_prime(self, num: mpz, prob_min: float = 0.99) -> bool:
        self._check_input(num, prob_min)
        round_count = self.get_round_count(prob_min)
        if num == 2 or num == 3:
            return True
        if num % 2 == 0:
            return False
        for _ in range(round_count):
            if not self._perform_test(num):
                return False
        return True

    @abstractmethod
    def _perform_test(self, num: mpz) -> bool:
        pass

    @abstractmethod
    def get_round_count(self, prob_min: float) -> int:
        pass

    def _check_input(self, num: mpz, prob_min: float) -> None:
        if num < 2:
            raise ValueError("Number must be >1")
        if not 0.5 <= prob_min < 1.0:
            raise ValueError("Probability in [0.5, 1.0)")

    def _gen_witness(self, num: mpz, mil_rob_flag: bool = False) -> mpz:
        end_val = num - 2 if mil_rob_flag else num - 1
        bit_len = (num - 1).bit_length()
        while True:
            witness = mpz(secrets.randbits(bit_len))
            if 2 <= witness <= end_val:
                return witness