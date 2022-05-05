import unittest
import src.inner_product.single_input_fe.fully_secure_fe.fully_secure_fe_lwe_short_int
from src.helpers.matrix import Matrix


class TestFullySecureFeLWEShortInt(unittest.TestCase):

    def setUp(self) -> None:
        self.fe = src.inner_product.single_input_fe.fully_secure_fe.fully_secure_fe_lwe_short_int

    def test_set_up(self):
        mpk, msk = self.fe.set_up(11, 10, 40, 40)
        self.assertIsInstance(mpk, dict)
        self.assertIsInstance(msk, Matrix)

    def test_func_key_generation(self):
        mpk, msk = self.fe.set_up(11, 10, 40, 40)
        func_key = self.fe.get_functional_key(mpk, msk, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        self.assertIsInstance(func_key, Matrix)

    def test_encryption(self):
        n = 11
        l = 10
        p, v = 40, 40
        mpk, msk = self.fe.set_up(n, l, p, v)
        x = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]
        c = self.fe.encrypt(mpk, x)
        self.assertIsInstance(c, dict)
        self.assertTrue("c0" in c)
        self.assertTrue("c1" in c)
        self.assertIsInstance(c["c0"], Matrix)
        self.assertIsInstance(c["c1"], Matrix)
        self.assertEqual(c["c1"].size(), (1, l))

    def test_decrypt(self):
        n = 11
        l = 10
        p, v = 40, 40
        mpk, msk = self.fe.set_up(n, l, p, v)
        x = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]
        y = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        c = self.fe.encrypt(mpk, x)
        func_key = self.fe.get_functional_key(mpk, msk, y)

        decrypted = self.fe.decrypt(mpk, func_key, y, c)
        self.assertIsInstance(decrypted, int)
        print(decrypted)


if __name__ == '__main__':
    unittest.main()
