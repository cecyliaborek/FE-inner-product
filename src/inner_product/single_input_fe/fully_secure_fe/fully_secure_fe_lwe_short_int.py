"""
Agrawal et al. Fully secure functional encryption scheme for inner product of short integer vectors, under the LWE
    assupmtion


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
from typing import List

import numpy as np
from charm.core.math.integer import randomPrime

from src.helpers.helpers import sample_random_matrix_mod, sample_random_matrix_from_normal_dist, \
    inner_product_modulo
from src.helpers.matrix import Matrix

debug = True


def set_up(n: int, vectors_len: int, message_bound: int, vector_bound: int):
    ip_bound = vectors_len * message_bound * vector_bound
    if debug: print("ip bound: ", ip_bound)
    ip_bound_bitsize = math.floor(math.log(ip_bound, 2)) + 1
    if debug: print((ip_bound_bitsize))
    q = int(randomPrime(64, 1))
    if debug: print("q: ", q)
    m_constraints = n * math.log(q, 2)
    m = np.random.randint(2 * m_constraints, 4 * m_constraints)
    if debug: print("m: ", m)
    alpha = random.random()
    A = sample_random_matrix_mod((m, n), q)
    Z = sample_random_matrix_mod((vectors_len, m), q)
    U = A.multipy_modulo(Z, q)
    mpk = {'A': A, 'U': U, 'K': ip_bound, 'P': message_bound, 'V': vector_bound, 'q': q, 'alpha': alpha}
    msk = Z
    return mpk, msk


def get_functional_key(msk: Matrix, y: List[int]):
    return msk @ Matrix.from_list(y)


def encrypt(mpk: dict, x: List[int]) -> dict:
    A = mpk['A']
    U = mpk['U']
    K = mpk['K']
    m, n = A.shape
    l = U.shape[0]
    alpha = mpk['alpha']
    q = mpk['q']
    s = sample_random_matrix_mod((n,), q)
    x = np.array(x)
    err0 = sample_random_matrix_from_normal_dist((m,), alpha * q)
    err1 = sample_random_matrix_from_normal_dist((l,), alpha * q)
    c0 = np.mod((multiply_matrices_mod(A, s, q) + err0), q)
    c1 = np.mod((multiply_matrices_mod(U, s, q) + err1 + math.floor(q / K) * x), q)
    return {'c0': c0, 'c1': c1}


def decrypt(mpk: dict, y: List[int], func_key, ciphertext: dict) -> int:
    q = mpk['q']
    c0 = ciphertext['c0']
    c1 = ciphertext['c1']
    ip_approx = (inner_product_modulo(y, c1, q) - inner_product_modulo(func_key, c0, q)) % q
    ip = ip_approx
    return ip
