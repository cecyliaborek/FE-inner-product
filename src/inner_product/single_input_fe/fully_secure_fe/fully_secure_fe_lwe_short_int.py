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


class FullySecureFeLweShortInt:

    def __init__(self, alpha=None, q=None):
        self.alpha = alpha
        self.q = q

    def set_up(self, n: int, vectors_len: int, message_bound: int, vector_bound: int):
        ip_bound = vectors_len * message_bound * vector_bound  # K in the paper
        if debug: print("ip bound: ", ip_bound)
        # ip_bound_bitsize = math.floor(math.log(ip_bound, 2)) + 1
        # if debug: print("ip bound bitsize: ", ip_bound_bitsize)
        self.q = int(randomPrime(1024, 1))
        if debug: print("q: ", self.q)
        m_constraints = n * math.log(self.q, 2)
        m = np.random.randint(2 * m_constraints, 4 * m_constraints)
        if debug: print("m: ", m)
        self.alpha = random.random()
        A = sample_random_matrix_mod((m, n), self.q)
        if debug: print("A dims: ", A.size())
        Z = sample_random_matrix_mod((vectors_len, m), self.q)
        if debug: print("Z dims: ", Z.size())
        U = Z.multiply_modulo(A, self.q)
        mpk = {'A': A, 'U': U, 'K': ip_bound, 'P': message_bound, 'V': vector_bound}
        msk = Z
        return mpk, msk

    def get_functional_key(self, msk: Matrix, y: List[int]) -> Matrix:
        y = reduce_vector_mod(y, self.q)
        return Matrix.from_list(y) @ msk

    def encrypt(self, mpk: dict, x: List[int]) -> Ciphertext:
        A = mpk['A']
        U = mpk['U']
        K = mpk['K']
        m, n = A.size()
        l = U.size()[0]
        s = sample_random_matrix_mod((1, n), self.q)
        x = Matrix.from_list(x)
        err0 = sample_random_matrix_from_normal_dist((1, m), self.alpha * self.q)
        err1 = sample_random_matrix_from_normal_dist((1, l), self.alpha * self.q)
        if debug: print("U dims: ", U.size())
        c0 = ((A.multiply_modulo(s.transpose(), self.q) + err0.transpose()) % self.q).transpose()
        c1 = ((U.multiply_modulo(s.transpose(), self.q) + err1.transpose() + math.floor(
            self.q / K) * x.transpose()) % self.q).transpose()
        return {'c0': c0, 'c1': c1}

    def decrypt(self, mpk: dict, y: List[int], func_key: Matrix, ciphertext: Ciphertext) -> int:
        ip_bound = mpk['K']
        c0 = ciphertext['c0'].to_list()[0]
        c1 = ciphertext['c1'].to_list()[0]
        ip_approx = (inner_product_modulo(y, c1, self.q) - inner_product_modulo(func_key.to_list()[0], c0, self.q)) \
                    % self.q
        ip_possible_values = [k for k in range(-1 * ip_bound + 1, ip_bound, 1)]
        f = ([abs((self.q / ip_bound) * k - ip_approx) for k in ip_possible_values])
        min_index = min(range(len(f)), key=f.__getitem__)
        ip = ip_possible_values[min_index]
        return ip
