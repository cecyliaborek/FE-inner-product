import numpy as np
import src.inner_product.single_input_fe.fully_secure_fe.fully_secure_fe_lwe_short_int


def test_final_result():

    fe = src.inner_product.single_input_fe.fully_secure_fe.fully_secure_fe_lwe_short_int

    x = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]
    y = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

    mpk, msk = fe.set_up(20, 10, 21, 11)
    c = fe.encrypt(mpk, x)
    func_key = fe.get_functional_key(mpk, msk, y)

    obtained_ip = fe.decrypt(mpk, func_key, y, c)
    expected_ip = np.inner(x, y)

    try:
        assert obtained_ip == expected_ip
    except AssertionError:
        print(f'The calculated inner product different than expected: {obtained_ip} != {expected_ip}')
    print(f'The calculated inner product same as expected!: {obtained_ip} == {expected_ip}')


if __name__ == "__main__":
    test_final_result()

