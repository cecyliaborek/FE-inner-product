import numpy as np
from ddh_pk_ip import DDH_PK

    

def testFinResult():
    fe = DDH_PK()
    mpk, msk = fe.setUp(8, 10)


    x = [1, 4, 6, 3, 5, 8, 9, 0, 3, 4]
    y = [1, 2, 1, 2, 1, 2, 1, 2, 1, 2]
    ciphertext = fe.encrypt(mpk, x)

    func_key = fe.getFunctionalKey(msk, y)

    final_result = fe.decrypt(mpk, ciphertext, func_key, y)
    expected = np.inner(x, y)

    try:
        assert final_result == expected
    except AssertionError:
        print(f'The calculated inner product different than expected: {final_result} != {expected}')


if __name__=="__main__":
    x = [1, 4, 6, 3, 5, 8, 9, 0, 3, 4]
    y = [1, 2, 1, 2, 1, 2, 1, 2, 1, 2]

    inner_prod = np.inner(x, y)

    print(inner_prod)
    
    testFinResult()