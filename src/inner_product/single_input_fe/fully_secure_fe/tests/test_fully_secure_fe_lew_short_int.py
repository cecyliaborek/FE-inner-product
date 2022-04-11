import unittest
import src.inner_product.single_input_fe.fully_secure_fe.fully_secure_fe_lwe_short_int
import numpy as np


class TestFullySecureFeLWEShortInt(unittest.TestCase):

    def setUp(self) -> None:
        self.fe = src.inner_product.single_input_fe.fully_secure_fe.fully_secure_fe_lwe_short_int

    def test_encrypt(self):
        mpk, msk = self.fe.set_up(10, 10, 40, 40)
        self.assertIsInstance(mpk, dict)
        self.assertIsInstance(msk, np.ndarray)


if __name__ == '__main__':
    unittest.main()
