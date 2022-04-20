import unittest

from src.errors.wrong_vector_for_provided_key import WrongVectorForProvidedKey
from src.helpers.helpers import inner_product
from src.inner_product.mife.mife_no_pairings.function_families import MultiInputInnerProductZl
import src.inner_product.mife.mife_no_pairings.one_time_secure_mife


class TestOneTimeSecureMIFE(unittest.TestCase):

    def setUp(self) -> None:
        self.mife = src.inner_product.mife.mife_no_pairings.one_time_secure_mife
        self.vector_len = 4
        self.inner_vector_len = 2
        self.mod = 60
        self.func_descr = MultiInputInnerProductZl(self.mod, self.vector_len, self.inner_vector_len)

    def test_set_up(self):
        key, pp = self.mife.set_up(self.func_descr, 2)
        self.assertIsInstance(key, list)
        self.assertEqual(len(key), self.vector_len)
        self.assertEqual(len(key[0]), self.inner_vector_len)

    def test_ith_encryption(self):
        key = [[33, 44], [23, 58], [32, 11], [11, 1]]
        pp = {'modulus': self.mod}
        x = [[10, 20], [30, 40], [50, 60], [70, 80]]
        i = 1
        c_i = self.mife.encrypt(key, pp, i, x[i])
        expected = [(x[i][j] + key[i][j]) % self.mod for j in range(2)]
        self.assertEqual(expected, c_i)

    def test_ith_encryption_exception(self):
        key = [[33, 44], [23, 58], [32, 11], [11, 1]]
        pp = {'modulus': self.mod}
        x = [[10, 20], [30, 40, 50], [50, 60], [70, 80]]
        i = 1
        self.assertRaises(WrongVectorForProvidedKey, self.mife.encrypt, key, pp, i, x[i])

    def test_func_key_generation(self):
        key = [[33, 44], [23, 58], [32, 11], [11, 1]]
        pp = {'modulus': self.mod}
        y = [[1, 2], [3, 4], [5, 6], [7, 8]]
        n = len(key)
        func_key = self.mife.get_functional_key(key, pp, y)
        expected_func_key = sum([inner_product(key[i], y[i]) for i in range(n)]) % self.mod
        self.assertEqual(expected_func_key, func_key)

    def test_func_key_generation_exception(self):
        key = [[33, 44], [23, 58], [32, 11], [11, 1]]
        pp = {'modulus': self.mod}
        y = [[1, 2], [3, 4], [5, 6]]
        self.assertRaises(WrongVectorForProvidedKey, self.mife.get_functional_key, key, pp, y)


if __name__ == '__main__':
    unittest.main()
