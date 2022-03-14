import numpy as np

from src.inner_product.ddh_pk_ip.ddh_pk_ip import DDH_PK


def testFinResult():
    fe = DDH_PK()

    x = [1, 4, 6, 3, 5]
    y = [1, 2, 1, 2, 1]
    n = len(x)

    mpk, msk = fe.setUp(1024, n)
    print('msk', type(msk))
    ciphertext = fe.encrypt(mpk, x)
    print('ciphertext', type(ciphertext['ct0']))
    print(ciphertext['ct0'])

    func_key = fe.getFunctionalKey(msk, y)

    final_result = fe.decrypt(mpk, ciphertext, func_key, y)
    expected = np.inner(x, y)

    try:
        assert final_result == expected
    except AssertionError:
        print(f'The calculated inner product different than expected: {final_result} != {expected}')
    print(f'The calculated inner product same as expected!: {final_result} == {expected}')


if __name__ == "__main__":
    testFinResult()
