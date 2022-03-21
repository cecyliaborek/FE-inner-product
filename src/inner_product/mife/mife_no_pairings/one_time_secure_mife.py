from src.errors.vector_size_mismatch_error import VectorSizeMismatchError
from src.errors.wrong_vector_for_provided_key import WrongVectorForProvidedKey
from src.helpers.helpers import inner_product, get_random_from_Zl, add_vectors_mod
from src.inner_product.mife.mife_no_pairings.function_families import MultiInputInnerProductZl
from typing import List


class OneTimeSecureMIFE:

    def __init__(self, func_descr: MultiInputInnerProductZl):
        self.vector_len = func_descr.n
        self.inner_vector_len = func_descr.m
        self.modulus = func_descr.L

    def set_up(self, security_param: int) -> List[List[int]]:
        key = [0] * self.vector_len
        for i in range(self.vector_len):
            key[i] = [get_random_from_Zl(self.modulus) for _ in range(self.inner_vector_len)]
        return key

    def encrypt(self, key: List[List[int]], i: int, x_i: List[int]) -> List[int]:
        if i > len(key):
            raise WrongVectorForProvidedKey(f'Index {i} out of range for key {key}')
        try:
            return add_vectors_mod(key[i], x_i, self.modulus)
        except VectorSizeMismatchError:
            raise WrongVectorForProvidedKey(f'Vector {x_i} too long for dimension {i} of the provided key')

    def get_functional_key(self, key: List[List[int]], y: List[List[int]]) -> int:
        if len(key) != len(y):
            raise WrongVectorForProvidedKey('Different lengths of the provided key and vector')
        n = len(key)
        intermediate = [None] * n
        for i in range(n):
            try:
                intermediate[i] = inner_product(key[i], y[i])
            except VectorSizeMismatchError:
                raise WrongVectorForProvidedKey(f'Different lengths of dimension {i} \
                for the provided key and the vector')
        return sum(intermediate) % self.modulus

    def decrypt(self, func_key: int, ciphertext: List[List[int]], y: List[List[int]]) -> int:
        if len(ciphertext) != len(y):
            raise WrongVectorForProvidedKey(f'Different lengths of provided ciphertext and vector')
        n = len(ciphertext)
        intermediate = [None] * n
        for i in range(n):
            try:
                intermediate[i] = inner_product(ciphertext[i], y[i])
            except VectorSizeMismatchError:
                raise WrongVectorForProvidedKey(f'Different lengths of dimension {i} \
                for the provided ciphertext and the vector')
        return (sum(intermediate) - func_key) % self.modulus
