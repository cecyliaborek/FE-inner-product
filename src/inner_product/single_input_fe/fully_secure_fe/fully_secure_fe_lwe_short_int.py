"""
Agrawal et al. Fully secure functional encryption scheme for inner product of short integer vectors, under the LWE
    assumption


| From:         Agrawal, Shweta, Benoît Libert, and Damien Stehlé. “Fully Secure Functional Encryption for Inner
                Products, from Standard Assumptions.”
| Published in: Advances in Cryptology – CRYPTO 2016. Vol. 9816. Berlin, Heidelberg: Springer Berlin Heidelberg, 2016.
                333–362. Web.
| DOI:          10.1007/978-3-662-53015-3_12

* type:         functional encryption
* setting:
* assumption:   LWE

:Authors:       Cecylia Borek
:Date:          04/2022
"""
import math
import random
from typing import List, Dict

import numpy as np
from charm.core.math.integer import randomPrime

from src.helpers.helpers import sample_random_matrix_mod, sample_random_matrix_from_normal_dist, \
    inner_product_modulo, reduce_vector_mod
from src.helpers.matrix import Matrix

Ciphertext = Dict[str, Matrix]

debug = True


def set_up(n: int, vectors_len: int, message_bound: int, vector_bound: int) -> (dict, Matrix):
    """Sets ups parameters needed for proper functioning of the scheme and returns master public and secret keys.

    Args:
        n:
        vectors_len: length of the vectors to encrypt and get functional key for
        message_bound: upper bound for integer components of vectors to encrypt
        vector_bound: upper bound for integer components of vectors to get functional key for

    Returns:
        tuple of master public key and master secret key

    """
    ip_bound = vectors_len * message_bound * vector_bound  # K in the paper
    if debug: print("ip bound: ", ip_bound)
    q = int(randomPrime(1024, 1))
    if debug: print("q: ", q)
    m_constraints = n * math.log(q, 2)
    m = np.random.randint(2 * m_constraints, 4 * m_constraints)
    if debug: print("m: ", m)
    alpha = random.random()
    A = sample_random_matrix_mod((m, n), q)
    if debug: print("A dims: ", A.size())
    Z = sample_random_matrix_mod((vectors_len, m), q)
    if debug: print("Z dims: ", Z.size())
    U = Z.multiply_modulo(A, q)
    mpk = {'A': A, 'U': U, 'K': ip_bound, 'P': message_bound, 'V': vector_bound, 'alpha': alpha, 'q': q}
    msk = Z
    return mpk, msk


def get_functional_key(mpk: dict, msk: Matrix, y: List[int]) -> Matrix:
    """Derives functional key for calculating inner product with vector y

    Args:
        mpk: the master public key
        msk: the master secret key
        y: vector of integer components to get functional key for

    Returns:
        the functional key corresponding to vector y
    """
    y = reduce_vector_mod(y, mpk['q'])
    return Matrix.from_list(y) @ msk


def encrypt(mpk: dict, x: List[int]) -> Ciphertext:
    """Encrypts integer vector x

    Args:
        mpk: master public key
        x: vector of integers to encrypt

    Returns:
        the ciphertext encrypting vector x

    """
    A = mpk['A']
    U = mpk['U']
    K = mpk['K']
    q = mpk['q']
    alpha = mpk['alpha']
    m, n = A.size()
    l = U.size()[0]
    s = sample_random_matrix_mod((1, n), q)
    x = Matrix.from_list(x)
    err0 = sample_random_matrix_from_normal_dist((1, m), alpha * q)
    err1 = sample_random_matrix_from_normal_dist((1, l), alpha * q)
    if debug: print("U dims: ", U.size())
    c0 = ((A.multiply_modulo(s.transpose(), q) + err0.transpose()) % q).transpose()
    c1 = ((U.multiply_modulo(s.transpose(), q) + err1.transpose() + math.floor(
        q / K) * x.transpose()) % q).transpose()
    return {'c0': c0, 'c1': c1}


def decrypt(mpk: dict, func_key: Matrix, y: List[int], ciphertext: Ciphertext) -> int:
    """Recovers the inner product of vectors x and y from x's ciphertext and y's functional key

    Args:
        mpk: the master public key
        func_key: the functional key for vector y
        y: vector for which the func key was calculated
        ciphertext: ciphertext encrypting vector x

    Returns:
        the inner product of vectors x and y
    """
    ip_bound = mpk['K']
    q = mpk['q']
    c0 = ciphertext['c0'].to_list()[0]
    c1 = ciphertext['c1'].to_list()[0]
    ip_approx = (inner_product_modulo(y, c1, q) - inner_product_modulo(func_key.to_list()[0], c0, q)) \
                % q
    ip_possible_values = [k for k in range(-1 * ip_bound + 1, ip_bound, 1)]
    f = ([abs((q / ip_bound) * k - ip_approx) for k in ip_possible_values])
    min_index = min(range(len(f)), key=f.__getitem__)
    ip = ip_possible_values[min_index]
    return ip
