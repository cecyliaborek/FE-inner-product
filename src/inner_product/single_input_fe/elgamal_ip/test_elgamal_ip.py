from elgamal_ip import ElGamalInnerProductFE
import numpy as np
import unittest


class TestElGamalInnerProduct(unittest.TestCase):

    def test_fin_result(self):

        fe = ElGamalInnerProductFE()
        pk, sk = fe.setUp(1024, 4)

        y = [1, 1, 1, 1]
        x = [1, 2, 3, 4]
        key_y = fe.getFunctionalKey(sk, y)
        c_x = fe.encrypt(pk, x)
        obtained_inner_prod = fe.decrypt(pk, c_x, key_y, y)
        expected_inner_prod = np.inner(x, y)

        try:
            assert obtained_inner_prod == expected_inner_prod
        except AssertionError:
            print(
                f'The calculated inner product different than expected: {obtained_inner_prod} != {expected_inner_prod}')
        print(f'The calculated inner product same as expected!: {obtained_inner_prod} == {expected_inner_prod}')


if __name__ == "__main__":
    unittest.main()
