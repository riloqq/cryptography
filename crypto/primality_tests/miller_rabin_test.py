from gmpy2 import mpz
import math
from crypto.primality_tests.base_primality_test import BasePrimalityTest
from crypto.services.number_service import NumberService


class MillerRabinTest(BasePrimalityTest):
    def get_round_count(self, prob_min: float) -> int:
        return math.ceil(-math.log(1 - prob_min) / math.log(4))

    def _perform_test(self, num: mpz) -> bool:
        factor_s, factor_t = self._extract_twos(num - 1)
        witness = self._gen_witness(num)
        x_val = NumberService.mod_pow(witness, factor_t, num)
        if x_val == 1 or x_val == num - 1:
            return True
        for _ in range(factor_s - 1):
            x_val = NumberService.mod_pow(x_val, mpz(2), num)
            if x_val == num - 1:
                return True
            if x_val == 1:
                return False
        return False


    def _extract_twos(self, num_minus_one: mpz) -> tuple[int, mpz]:
        s_val = 0
        t_val = num_minus_one
        while t_val % 2 == 0:
            s_val += 1
            t_val //= 2
        return s_val, t_val