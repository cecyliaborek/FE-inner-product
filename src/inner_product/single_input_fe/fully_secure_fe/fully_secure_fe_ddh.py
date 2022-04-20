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
        self.group = group
        self.gen1 = gen1
        self.gen2 = gen2
        self.p = p

    def get_public_params(self):
        return {'group': self.group, 'gen1': self.gen1, 'gen2': self.gen2, 'p': self.p}

    def set_up(self, security_param: int, vector_length: int) -> (dict, dict):
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
        y = reduce_vector_mod(y, self.p)
        func_key = {'s_y': inner_product_group_vector(msk['s'], y), 't_y': inner_product_group_vector(msk['t'], y)}
        return func_key

    def encrypt(self, mpk: dict, x: List[int]) -> dict:
        ciphertext = {}
        x = reduce_vector_mod(x, self.p)
        r = self.group.random()
        ciphertext['c'] = self.gen1 ** r
        ciphertext['d'] = self.gen2 ** r
        ciphertext['e'] = [(self.gen1 ** x[i]) * (mpk['h'][i] ** r) for i in range(len(x))]
        return ciphertext

    def decrypt(self, func_key: dict, ciphertext: dict, y: List[int], limit: int) -> int:
        e = ciphertext['e']
        intermediate = np.prod([e[i] ** y[i] for i in range(len(y))]) / (
                ciphertext['c'] ** func_key['s_y'] * ciphertext['d'] ** func_key['t_y']
        )
        return dummy_discrete_log(get_int(self.gen1), get_int(intermediate), get_modulus(self.gen1), limit)
