import unittest

from src.helpers.helpers import inner_product_matrices
from src.inner_product.mife.mife_no_pairings.function_families import MultiInputInnerProductZl
from src.inner_product.mife.mife_no_pairings.mife_no_pairings import MIFENoPairingsModuloL


class TestMIFENoPairings(unittest.TestCase):
    def setUp(self) -> None:
        ip_zl_func_descr = MultiInputInnerProductZl(60, 2, 4)
        self.mife = MIFENoPairingsModuloL(ip_zl_func_descr)
        self.mpk, self.msk = self.mife.set_up_keys(1024)

    def test_final_result(self):
        x = [[1, 2], [3, 4], [5, 6], [7, 8]]
        y = [[11, 3], [4, 16], [54, 30], [22, 22]]

        ciphertexts = []
        for i in range(len(x)):
            ciphertexts.append(self.mife.encrypt(self.mpk, self.msk, i, x[i]))

        func_key = self.mife.get_functional_key(self.msk, y)

        result_inner_prod = self.mife.decrypt(self.mpk, func_key, ciphertexts, y)
        expected_inner_prod = inner_product_matrices(x, y) % self.mife.modulus
        self.assertEqual(expected_inner_prod, result_inner_prod,
                         f'Expected = {expected_inner_prod}, obtained = {result_inner_prod}')


if __name__ == '__main__':
    unittest.main()
