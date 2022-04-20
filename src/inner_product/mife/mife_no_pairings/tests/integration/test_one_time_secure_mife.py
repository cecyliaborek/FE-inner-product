import unittest

from src.helpers.helpers import inner_product
from src.inner_product.mife.mife_no_pairings.function_families import MultiInputInnerProductZl
import src.inner_product.mife.mife_no_pairings.one_time_secure_mife


class TestOneTimeSecureMIFE(unittest.TestCase):

    def setUp(self) -> None:
        self.modulus = 60
        self.vector_len = 4
        self.inner_vector_len = 2
        self.mife = src.inner_product.mife.mife_no_pairings.one_time_secure_mife

    def test_final_result(self):
        key, pp = self.mife.set_up(MultiInputInnerProductZl(self.modulus, self.vector_len, self.inner_vector_len), 2)
        x = [[10, 20], [30, 4], [50, 60], [70, 80]]
        y = [[1, 2], [3, 4], [5, 6], [7, 8]]
        ciphertext = []
        for i in range(len(x)):
            ciphertext.append(self.mife.encrypt(key, pp, i, x[i]))
        func_key = self.mife.get_functional_key(key, pp, y)
        result_ip = self.mife.decrypt(func_key, pp, ciphertext, y)
        expected_ip = sum([inner_product(x[i], y[i]) for i in range(len(x))]) % self.modulus
        self.assertEqual(expected_ip, result_ip)
        print(expected_ip, result_ip)


if __name__ == '__main__':
    unittest.main()
