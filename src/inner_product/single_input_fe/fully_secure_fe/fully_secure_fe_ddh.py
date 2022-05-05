"""
Agrawal et al. Fully secure functional encryption scheme from DDH


| From:         Agrawal, Shweta, Benoît Libert, and Damien Stehlé. “Fully Secure Functional Encryption for Inner
                Products, from Standard Assumptions.”
| Published in: Advances in Cryptology – CRYPTO 2016. Vol. 9816. Berlin, Heidelberg: Springer Berlin Heidelberg, 2016.
                333–362. Web.
| DOI:          10.1007/978-3-662-53015-3_12

* type:         functional encryption
* setting:
* assumption:   DDH

:Authors:       Cecylia Borek
:Date:          03/2022

Note: Because to recover the final result of inner product discrete logarithm calculation is needed, the inner product
should lie within a reasonable limit, otherwise the calculation may take too long.
"""
from src.helpers.helpers import generate_group, get_random_generator, inner_product_group_vector, dummy_discrete_log, \
    get_int, get_modulus, reduce_vector_mod

from typing import List
import numpy as np


def set_up(security_param: int, vector_length: int) -> (dict, dict):
    """Sets up parameters needed for proper functioning of the scheme and generates master public and secret keys.

    Args:
        security_param: security parameter
        vector_length: supported length of integer vectors

    Returns:
        (dict, dict): master public key and master secret key
    """
    group = generate_group(security_param)
    gen1 = get_random_generator(group)
    gen2 = get_random_generator(group)
    p = get_modulus(gen1)
    s = [group.random() for _ in range(vector_length)]
    t = [group.random() for _ in range(vector_length)]
    h = [(gen1 ** s[i]) * (gen2 ** t[i]) for i in range(vector_length)]
    mpk, msk = {'group': group, 'gen1': gen1, 'gen2': gen2, 'p': p, 'h': h}, {'s': s, 't': t}
    return mpk, msk


def get_functional_key(mpk: dict, msk: dict, y: List[int]) -> dict:
    """Derives functional key for calculating inner product with vector y

    Args:
        mpk: master public key
        msk: master secret key
        y: integer vector y for which the functional key will be generated

    Returns:
        dict: functional key corresponding to vector y
    """
    y = reduce_vector_mod(y, mpk['p'])
    func_key = {'s_y': inner_product_group_vector(msk['s'], y), 't_y': inner_product_group_vector(msk['t'], y)}
    return func_key


def encrypt(mpk: dict, x: List[int]) -> dict:
    """Encrypts integer vector x

    Args:
        mpk: master public key
        x: integer vector to be encrypted

    Returns:
        dict: ciphertext corresponding to vector x
    """
    ciphertext = {}
    x = reduce_vector_mod(x, mpk['p'])
    r = mpk['group'].random()
    ciphertext['c'] = mpk['gen1'] ** r
    ciphertext['d'] = mpk['gen2'] ** r
    ciphertext['e'] = [(mpk['gen1'] ** x[i]) * (mpk['h'][i] ** r) for i in range(len(x))]
    return ciphertext


def decrypt(mpk: dict, func_key: dict, ciphertext: dict, y: List[int], limit: int) -> int:
    """Recovers the inner product of vectors x and y from x's ciphertext and functional key for y

    Args:
        mpk: master public key
        func_key: functional key for vector y
        ciphertext: ciphertext encrypting vector x
        y: vector y
        limit: An upper limit up to which the inner product should be searched for

    Returns:
        int: the inner product of x and y if it was found within the limit, otherwise None

    """
    e = ciphertext['e']
    intermediate = np.prod([e[i] ** y[i] for i in range(len(y))]) / (
            ciphertext['c'] ** func_key['s_y'] * ciphertext['d'] ** func_key['t_y']
    )
    return dummy_discrete_log(get_int(mpk['gen1']), get_int(intermediate), get_modulus(mpk['gen1']), limit)

