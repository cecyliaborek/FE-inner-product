import unittest

from src.errors.wrong_vector_for_provided_key import WrongVectorForProvidedKey
import src.inner_product.single_input_fe.elgamal_ip.elgamal_ip
from src.inner_product.mife.mife_no_pairings.function_families import MultiInputInnerProductZl
from src.inner_product.mife.mife_no_pairings.mife_no_pairings_modulo import MPK, MSK, FunctionalKey
import src.inner_product.mife.mife_no_pairings.mife_no_pairings_modulo


class TestMIFENoPairings(unittest.TestCase):
    def setUp(self) -> None:
        self.ip_zl_func_family = MultiInputInnerProductZl(60, 2, 4)
        self.mife = src.inner_product.mife.mife_no_pairings.mife_no_pairings_modulo

    def test_set_up_keys(self):
        mpk, msk = self.mife.set_up(func_descr=self.ip_zl_func_family, security_param=1024)
        self.assertIsInstance(mpk, MPK)
        self.assertIsInstance(msk, MSK)

    def test_ith_encrypt(self):
        mpk, msk = self.mife.set_up(self.ip_zl_func_family, 1024)
        i = 0
        x = [[1, 2], [3, 4], [5, 6], [7, 8]]
        actual_ciphertext = self.mife.encrypt(mpk,  msk, i, x[i])
        self.assertIsInstance(actual_ciphertext, dict)
        self.assertIsInstance(actual_ciphertext['ct'], list)

    def test_ith_encrypt_exception(self):
        mpk, msk = self.mife.set_up(self.ip_zl_func_family, 1024)
        i = 0
        x = [[1, 2, 3], [3, 4, 5], [5, 6, 7], [7, 8, 9]]
        self.assertRaises(WrongVectorForProvidedKey, self.mife.encrypt, mpk, msk, i, x[i])

    def test_func_key_generation(self):
        mpk, msk = self.mife.set_up(self.ip_zl_func_family, 1024)
        y = [[1, 2], [3, 4], [5, 6], [7, 8]]
        func_key = self.mife.get_functional_key(mpk, msk, y)
        self.assertIsInstance(func_key, FunctionalKey)

    def test_decrypt(self):
        mpk, msk = self.mife.set_up(self.ip_zl_func_family, 1024)
        x = [[1, 2], [3, 4], [5, 6], [7, 8]]
        y = [[1, 2], [3, 4], [5, 6], [7, 8]]
        c = []
        for i in range(len(x)):
            c.append(self.mife.encrypt(mpk, msk, i, x[i]))
        func_key = self.mife.get_functional_key(mpk, msk, y)

        result = self.mife.decrypt(mpk, func_key, c, y, 2000)
        self.assertIsInstance(result, int)


if __name__ == '__main__':
    unittest.main()
