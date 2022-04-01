import numpy as np

from src.inner_product.single_input_fe.fully_secure_fe.fully_secure_fe_ddh import FullySecureFE


def test_fin_result():
    x = [1, 4, 6, 3, 5]
    y = [1, 2, 1, 9, 1]
    n = len(x)

    mpk, msk = FullySecureFE.set_up_keys(1024, n)
    print('msk', type(msk))
    ciphertext = FullySecureFE.encrypt(mpk, x)
    print(ciphertext)

    func_key = FullySecureFE.get_functional_key(msk, y)

    final_result = FullySecureFE.decrypt(mpk, func_key, ciphertext, y, 200)
    expected = np.inner(x, y)

    try:
        assert final_result == expected
    except AssertionError:
        print(f'The calculated inner product different than expected: {final_result} != {expected}')
    print(f'The calculated inner product same as expected!: {final_result} == {expected}')


if __name__ == "__main__":
    test_fin_result()
