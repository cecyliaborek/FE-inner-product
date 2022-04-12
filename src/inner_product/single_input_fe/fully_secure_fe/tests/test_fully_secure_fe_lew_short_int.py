import unittest
import src.inner_product.single_input_fe.fully_secure_fe.fully_secure_fe_lwe_short_int
from src.helpers.matrix import Matrix
import numpy as np


class TestFullySecureFeLWEShortInt(unittest.TestCase):

    def setUp(self) -> None:
        self.fe = src.inner_product.single_input_fe.fully_secure_fe.fully_secure_fe_lwe_short_int

    def test_encrypt(self):
        mpk, msk = self.fe.set_up(10, 10, 40, 40)
        self.assertIsInstance(mpk, dict)
        self.assertIsInstance(msk, Matrix)

    def test_func_key_generation(self):
        mpk, msk = self.fe.set_up(10, 10, 40, 40)
        func_key = self.fe.get_functional_key(msk, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        self.assertIsInstance(func_key, Matrix)


if __name__ == '__main__':
    unittest.main()
