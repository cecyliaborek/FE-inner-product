from src.errors.vector_size_mismatch_error import VectorSizeMismatchError
from src.errors.wrong_vector_for_provided_key import WrongVectorForProvidedKey
from src.helpers.helpers import inner_product_modulo, inner_product, get_random_from_Zl, add_vectors_mod
from src.inner_product.mife.mife_no_pairings.function_families import MultiInputInnerProductZl
from typing import List


class OneTimeSecureMIFE:

    def __init__(self):
        self.vector_len = None
        self.modulus = None
        self.inner_vector_len = None

    def set_up(self, security_param: int, func_descr: MultiInputInnerProductZl) -> List[List[int]]:
        self.vector_len = func_descr.n
        self.inner_vector_len = func_descr.m
        self.modulus = func_descr.L
        u = [0] * self.vector_len
        for i in range(self.vector_len):
            u[i] = [get_random_from_Zl(self.modulus) for _ in range(self.inner_vector_len)]
        return u

    def encrypt(self, u, i, x_i):
        if i > len(u):
            raise WrongVectorForProvidedKey(f'Index {i} out of range for key {u}')
        try:
            return add_vectors_mod(u[i], x_i, self.modulus)
        except VectorSizeMismatchError:
            if len(x_i) < len(u):
                raise WrongVectorForProvidedKey(f'Vector {x_i} too short provided key')
            raise WrongVectorForProvidedKey(f'Vector {x_i} too long for provided key')

    def get_functional_key(self, u: List[int], y: List[int]):
        # todo: update to vector of vectors support
        try:
            return inner_product_modulo(u, y, self.modulus)
        except VectorSizeMismatchError:
            if len(y) < len(u):
                raise WrongVectorForProvidedKey(f'Vector {y} too short provided key')
            raise WrongVectorForProvidedKey(f'Vector {y} too long for provided key')

    def decrypt(self, func_key, ciphertext, y):
        try:
            return (inner_product(ciphertext, y) - func_key) % self.modulus
        except VectorSizeMismatchError:
            if len(y) < len(ciphertext):
                raise WrongVectorForProvidedKey(f'Vector {y} too short provided ciphertext')
            raise WrongVectorForProvidedKey(f'Vector {y} too long for provided ciphertext')
