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
from src.helpers.helpers import sample_random_matrix_mod, multiply_matrices_mod, sample_random_matrix_from_normal_dist
from charm.core.math.integer import randomPrime

from typing import List
import numpy as np
import math


def set_up(n: int, vectors_len: int, message_bound: int, vector_bound: int):
    ip_bound = vectors_len * message_bound * vector_bound
    ip_bound_bitsize = math.floor(math.log(ip_bound, 2)) + 1
    q = randomPrime(ip_bound_bitsize * 100000)
    m_constraints = n * math.log(q, 2)
    m = np.random.randint(2 * m_constraints, 4 * m_constraints)
    A = sample_random_matrix_mod((m, n), q)
    Z = sample_random_matrix_mod((vectors_len, m), q)
    U = multiply_matrices_mod(A, Z, q)
    mpk = {'A': A, 'U': U, 'K': ip_bound, 'P': message_bound, 'V': vector_bound}
    msk = Z
    return mpk, msk


def get_functional_key(msk: np.ndarray, y: List[int]):
    y_arr = np.array(y)
    return np.multiply(y_arr, msk)


def encrypt(mpk: dict, x: List[int]) -> dict:
    A = mpk['A']
    U = mpk['U']
    m = A.shape[0]
    n = A.shape[1]
    l = U.shape[0]
    alpha = mpk['alpha']
    q = mpk['q']
    s = sample_random_matrix_mod((n,), q)
    err0 = sample_random_matrix_from_normal_dist((m,), alpha * q)
    err1 = sample_random_matrix_from_normal_dist((l,), alpha * q)
    c0 = multiply_matrices_mod(A, s, q) + err0
    c1 = multiply_matrices_mod(U, s, q) + err1 + x
