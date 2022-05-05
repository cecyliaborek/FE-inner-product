import unittest

from src.helpers.helpers import inner_product_matrices
from src.inner_product.mife.mife_no_pairings.function_families import MultiInputInnerProductZl
import src.inner_product.mife.mife_no_pairings.mife_no_pairings_modulo


class TestMIFENoPairings(unittest.TestCase):
    def setUp(self) -> None:
        ip_zl_func_descr = MultiInputInnerProductZl(60, 4, 2)
        self.mife = src.inner_product.mife.mife_no_pairings.mife_no_pairings_modulo
        self.mpk, self.msk = self.mife.set_up(ip_zl_func_descr, 1024)

    def test_final_result(self):
        x = [[1, 2], [3, 4], [5, 6], [7, 8]]
        y = [[11, 3], [4, 16], [54, 30], [22, 22]]

        ciphertexts = []
        for i in range(len(x)):
            ciphertexts.append(self.mife.encrypt(self.mpk, self.msk, i, x[i]))

        func_key = self.mife.get_functional_key(self.mpk, self.msk, y)

        result_inner_prod = self.mife.decrypt(self.mpk, func_key, ciphertexts, y, 2000)
        expected_inner_prod = inner_product_matrices(x, y) % self.mpk.ot_mife_modulus
        self.assertEqual(expected_inner_prod, result_inner_prod,
                         f'Expected = {expected_inner_prod}, obtained = {result_inner_prod}')


if __name__ == '__main__':
    unittest.main()
