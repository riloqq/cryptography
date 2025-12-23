from gmpy2 import mpz

class NumberService:
    @staticmethod
    def mod_pow(base_val: mpz, exp_val: mpz, mod_val: mpz) -> mpz:
        if mod_val <= 0:
            raise ValueError("Modulus positive")
        if exp_val < 0:
            raise ValueError("Exponent non-negative")
        result_val = mpz(1)
        base_val %= mod_val
        while exp_val > 0:
            if exp_val % 2 == 1:
                result_val = (result_val * base_val) % mod_val
            base_val = (base_val * base_val) % mod_val
            exp_val >>= 1
        return result_val % mod_val