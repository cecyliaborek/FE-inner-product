import unittest

from src.errors.wrong_vector_for_provided_key import WrongVectorForProvidedKey
from src.helpers.helpers import inner_product
from src.inner_product.mife.mife_no_pairings.function_families import MultiInputInnerProductZl
from src.inner_product.mife.mife_no_pairings.one_time_secure_mife import OneTimeSecureMIFE


class TestOneTimeSecureMIFE(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ip_zl_func_family = MultiInputInnerProductZl(60, 2, 4)
        cls.mife = OneTimeSecureMIFE(ip_zl_func_family)

    def test_secret_key_gen(self):
        key = self.mife.set_up(2)
        self.assertIsInstance(key, list)
        self.assertEqual(len(key), self.mife.vector_len)
        self.assertEqual(len(key[0]), self.mife.inner_vector_len)

    def test_ith_encryption(self):
        key = [[33, 44], [23, 58], [32, 11], [11, 1]]
        x = [[10, 20], [30, 40], [50, 60], [70, 80]]
        i = 1
        c_i = self.mife.encrypt(key, i, x[i])
        expected = [(x[i][j] + key[i][j]) % self.mife.modulus for j in range(2)]
        self.assertEqual(expected, c_i)

    def test_ith_encryption_exception(self):
        key = [[33, 44], [23, 58], [32, 11], [11, 1]]
        x = [[10, 20], [30, 40, 50], [50, 60], [70, 80]]
        i = 1
        self.assertRaises(WrongVectorForProvidedKey, self.mife.encrypt, key, i, x[i])

    def test_func_key_generation(self):
        key = [[33, 44], [23, 58], [32, 11], [11, 1]]
        y = [[1, 2], [3, 4], [5, 6], [7, 8]]
        n = len(key)
        func_key = self.mife.get_functional_key(key, y)
        expected_func_key = sum([inner_product(key[i], y[i]) for i in range(n)]) % self.mife.modulus
        self.assertEqual(expected_func_key, func_key)

    def test_func_key_generation_exception(self):
        key = [[33, 44], [23, 58], [32, 11], [11, 1]]
        y = [[1, 2], [3, 4], [5, 6]]
        self.assertRaises(WrongVectorForProvidedKey, self.mife.get_functional_key, key, y)


if __name__ == '__main__':
    unittest.main()
