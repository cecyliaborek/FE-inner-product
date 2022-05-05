import numpy as np

import src.inner_product.single_input_fe.fully_secure_fe.fully_secure_fe_ddh


def test_fin_result():
    x = [1, 4, 6, 3, 5]
    y = [1, 2, 1, 9, 1]
    n = len(x)

    fe = src.inner_product.single_input_fe.fully_secure_fe.fully_secure_fe_ddh

    mpk, msk = fe.set_up(1024, n)
    print('msk', type(msk))
    ciphertext = fe.encrypt(mpk, x)
    print(ciphertext)

    func_key = fe.get_functional_key(mpk, msk, y)

    final_result = fe.decrypt(mpk, func_key, ciphertext, y, 200)
    expected = np.inner(x, y)

    try:
        assert final_result == expected
    except AssertionError:
        print(f'The calculated inner product different than expected: {final_result} != {expected}')
    print(f'The calculated inner product same as expected!: {final_result} == {expected}')


if __name__ == "__main__":
    test_fin_result()
