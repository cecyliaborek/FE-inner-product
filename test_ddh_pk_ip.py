import numpy as np
from ddh_pk_ip import DDH_PK

    

def testFinResult():
    fe = DDH_PK()
    mpk, msk = fe.setUp(8, 10)


    x = [1, 4, 6, 3, 5, 8, 9, 0, 3, 4]
    y = [1, 2, 1, 2, 1, 2, 1, 2, 1, 2]
    ciphertext = fe.encrypt(mpk, x)

    func_key = fe.deriveFunctionalKey(msk, y)

    final_result = fe.decrypt(mpk, ciphertext, func_key, y)

    inner_prod = np.inner(x, y)

    print(final_result)

    assert final_result == inner_prod


if __name__=="__main__":
    x = [1, 4, 6, 3, 5, 8, 9, 0, 3, 4]
    y = [1, 2, 1, 2, 1, 2, 1, 2, 1, 2]

    inner_prod = np.inner(x, y)

    print(inner_prod)
    
    testFinResult()