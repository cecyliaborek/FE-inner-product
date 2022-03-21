import unittest

from src.inner_product.mife.mife_no_pairings.function_families import MultiInputInnerProductZl
from src.inner_product.mife.mife_no_pairings.one_time_secure_mife import OneTimeSecureMIFE


class TestOneTimeSecureMIFE(unittest.TestCase):

    def setUp(self) -> None:
        ip_zl_func_family = MultiInputInnerProductZl(60, 2, 4)
        self.mife = OneTimeSecureMIFE(ip_zl_func_family)

    def test_final_result(self):
        key = self.mife.set_up(2)
        x = [[10, 20], [30, 40], [50, 60], [70, 80]]
        y = [[1, 2], [3, 4], [5, 6], [7, 8]]
        ciphertext = []
        for i in range(len(x)):
            ciphertext.append(self.mife.encrypt(key, i, x[i]))
        func_key = self.mife.get_functional_key(key, y)
        result_ip = self.mife.decrypt(func_key, ciphertext, y)
        print(result_ip)


if __name__ == '__main__':
    unittest.main()
