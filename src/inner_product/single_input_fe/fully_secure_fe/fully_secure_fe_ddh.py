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
    get_int, get_modulus

from typing import List
import numpy as np


class MasterPublicKey:

    def __init__(self, group, gen1, gen2, h):
        self.group = group
        self.gen1 = gen1
        self.gen2 = gen2
        self.h = h


class MasterSecretKey:

    def __init__(self, s, t):
        self.s = s
        self.t = t


class FullySecureFE:

    @staticmethod
    def set_up_keys(security_param: int, vector_length: int) -> (MasterPublicKey, MasterSecretKey):
        group = generate_group(security_param)
        g = get_random_generator(group)
        f = get_random_generator(group)
        s = [group.random() for _ in range(vector_length)]
        t = [group.random() for _ in range(vector_length)]
        h = [(g ** s[i]) * (f ** t[i]) for i in range(vector_length)]
        mpk, msk = MasterPublicKey(group, g, f, h), MasterSecretKey(s, t)
        return mpk, msk

    @staticmethod
    def get_functional_key(msk: MasterSecretKey, y: List[int]) -> dict:
        func_key = {'s_y': inner_product_group_vector(msk.s, y), 't_y': inner_product_group_vector(msk.t, y)}
        return func_key

    @staticmethod
    def encrypt(mpk: MasterPublicKey, x: List[int]) -> dict:
        ciphertext = {}
        r = mpk.group.random()
        ciphertext['c'] = mpk.gen1 ** r
        ciphertext['d'] = mpk.gen2 ** r
        ciphertext['e'] = [(mpk.gen1 ** x[i]) * (mpk.h[i] ** r) for i in range(len(x))]
        return ciphertext

    @staticmethod
    def decrypt(mpk: MasterPublicKey, func_key: dict, ciphertext: dict, y: List[int], limit: int) -> int:
        e = ciphertext['e']
        intermediate = np.prod([e[i] ** y[i] for i in range(len(y))])/(
            ciphertext['c'] ** func_key['s_y'] * ciphertext['d'] ** func_key['t_y']
        )
        return dummy_discrete_log(get_int(mpk.gen1), get_int(intermediate), get_modulus(mpk.gen1), limit)


