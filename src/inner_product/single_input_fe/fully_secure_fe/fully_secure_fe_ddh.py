"""
Agrawal et al. Fully secure functional encryption scheme from standard assumptions


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
"""
from src.helpers.helpers import generate_group, get_random_generator, inner_product_group_vector, dummy_discrete_log, \
    get_int, get_modulus, reduce_vector_mod

from typing import List
import numpy as np


class FullySecureFE:

    def __init__(self, group=None, gen1=None, gen2=None, p=None):
        """
        Initializes an instance of Fully Secure Inner Product FE scheme.
        If we want to make this instance compatible with some other (e.g. to be able to decrypt messages encrypted by
        the other instance) we should provide the public parameters of the other instance. The set_up method will
        overwrite the provided parameters
        Args:
            group: public group of the other instance
            gen1: random generator of the group
            gen2: second random generator of the group
            p: order of the group
        """
        self.group = group
        self.gen1 = gen1
        self.gen2 = gen2
        self.p = p

    def get_public_params(self):
        """
        Returns parameters allowing for initialization of compatible instance of a scheme elsewhere (e.g. to be able to
        decrypt messages encrypted by the other instance)
        Returns:
            dict of parameters of the scheme
        """
        return {'group': self.group, 'gen1': self.gen1, 'gen2': self.gen2, 'p': self.p}

    def set_up(self, security_param: int, vector_length: int) -> (dict, dict):
        """
        Sets up parameters needed for proper functioning of the scheme. After calling, the get_public_params function
        may be called to obtain parameters needed for initializing a compatible instance of the scheme.
        Args:
            security_param: security parameter
            vector_length: supported length of integer vectors

        Returns:
            (dict, dict): master public key and master secret key
        """
        self.group = generate_group(security_param)
        self.gen1 = get_random_generator(self.group)
        self.gen2 = get_random_generator(self.group)
        self.p = get_modulus(self.gen1)
        s = [self.group.random() for _ in range(vector_length)]
        t = [self.group.random() for _ in range(vector_length)]
        h = [(self.gen1 ** s[i]) * (self.gen2 ** t[i]) for i in range(vector_length)]
        mpk, msk = {'h': h}, {'s': s, 't': t}
        return mpk, msk

    def get_functional_key(self, msk: dict, y: List[int]) -> dict:
        """
        Generates a functional key for integer vector y
        Args:
            msk: master secret key
            y: integer vector y for which the functional key will be generated

        Returns:
            dict: functional key corresponding to vector y
        """
        y = reduce_vector_mod(y, self.p)
        func_key = {'s_y': inner_product_group_vector(msk['s'], y), 't_y': inner_product_group_vector(msk['t'], y)}
        return func_key

    def encrypt(self, mpk: dict, x: List[int]) -> dict:
        """
        Encrypts integer vector x
        Args:
            mpk: master public key
            x: integer vector to be encrypted

        Returns:
            dict: ciphertext corresponding to vector x
        """
        ciphertext = {}
        x = reduce_vector_mod(x, self.p)
        r = self.group.random()
        ciphertext['c'] = self.gen1 ** r
        ciphertext['d'] = self.gen2 ** r
        ciphertext['e'] = [(self.gen1 ** x[i]) * (mpk['h'][i] ** r) for i in range(len(x))]
        return ciphertext

    def decrypt(self, func_key: dict, ciphertext: dict, y: List[int], limit: int) -> int:
        """
        Recovers the inner product of vectors x and y from x's ciphertext and functional key for y
        Args:
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
        return dummy_discrete_log(get_int(self.gen1), get_int(intermediate), get_modulus(self.gen1), limit)
