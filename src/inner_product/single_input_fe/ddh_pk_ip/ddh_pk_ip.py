"""
Michel Abdalla et al. DDH based simple functional encryption inner product scheme

| From: Abdalla, Michel et al. “Simple Functional Encryption Schemes for Inner Products.” 
| Published in: Public-Key Cryptography -- PKC 2015. Berlin, Heidelberg: 
|               Springer Berlin Heidelberg, 2015. 733–751. Web.
| DOI: 10.1007/978-3-662-46447-2_33

* type:         functional encryption (public key)
* setting:      SchnorrGroup mod p
* assumption:   DDH

:Authors: Cecylia Borek
:Date: 02/2022
"""
from typing import Dict, List, Tuple
import numpy as np
import charm

from src.helpers.helpers import generate_group, get_modulus, reduce_vector_mod, inner_product_group_vector, get_int, \
    dummy_discrete_log, get_random_generator
from src.errors.wrong_vector_for_provided_key import WrongVectorForProvidedKey

IntegerGroupElement = charm.core.math.integer.integer


class PublicKeyDDHFe:

    def __init__(self, group=None, g=None, p=None) -> None:
        self.group = group
        self.g = g
        self.p = p

    def get_public_params(self) -> dict:
        """
        Returns public parameters allowing for instantiation of compatible instance of FE elsewhere.
        Returns:
            dict: dictionary containing public parameters of the scheme

        """
        return {'group': self.group, 'g': self.g, 'p': self.p}

    def set_up(self, security_parameter: int, vector_length: int) -> \
            (List[IntegerGroupElement], List[IntegerGroupElement]):
        """Configures instance of DDH public key FE scheme.
        Samples an integer Schnorr group of order p, where p is a prime number of
        bit-size equal to security_parameter. The public parameters describing the
        sampled group are saved as class instance members. Sets the supported message
        (vector) length to vector_length. Returns master public key and master secret 
        key as vectors of group elements.

        Args:
            security_parameter (int): security parameter, bit-size of order of the sampled group
            vector_length (int): supported vector length

        Returns:
            Tuple[List[IntegerGroupElement], List[IntegerGroupElement]]: master public key,
                                                                            master secret key
        """
        self.group = generate_group(security_parameter)
        self.g = get_random_generator(self.group)
        self.p = get_modulus(self.g)
        s = [self.group.random() for _ in range(vector_length)]
        h = [self.g ** s[i] for i in range(vector_length)]
        mpk = h
        msk = s
        return mpk, msk

    def encrypt(self, mpk: List[IntegerGroupElement], x: List[int]) -> Dict[str, List[IntegerGroupElement]]:
        """Encrypts integer vector x

        Args:
            mpk (List[IntegerGroupElement]): master public key
            x (List[int]): integer vector to be encrypted

        Raises:
            WrongVectorSizeError: if the provided vector is longer than supported vector length

        Returns:
            Dict[str, List[IntegerGroupElement]]: ciphertext corresponding to vector x
        """
        if len(x) > len(mpk):
            raise WrongVectorForProvidedKey(f'Vector {x} too long for the configured FE')
        r = self.group.random()
        ct_0 = self.g ** r
        x = reduce_vector_mod(x, self.p)
        ct = [(mpk[i] ** r) * (self.g ** x[i]) for i in range(len(x))]
        ciphertext = {'ct0': ct_0, 'ct': ct}
        return ciphertext

    def get_functional_key(self, msk: List[IntegerGroupElement], y: List[int]) -> int:
        """Derives functional key for calculating inner product with vector y

        Args:
            msk (List[IntegerGroupElement]): master secret key
            y (List[int]): vector for which the functional key should be calculatd

        Raises:
            WrongVectorSizeError: if the vector y is longer than the supported vector length

        Returns:
            int: Functional key corresponding to vector y
        """
        if len(y) > len(msk):
            raise WrongVectorForProvidedKey(f'Vector {y} too long for the configured FE')
        y = reduce_vector_mod(y, self.p)
        return inner_product_group_vector(msk, y)

    def decrypt(self, mpk, ciphertext: Dict[str, IntegerGroupElement], sk_y: int, y: List[int], limit: int) -> int:
        """Returns inner product of vector y and vector x encrypted in ciphertext if it lies within the provided limit

        Args:
            mpk (_type_): _description_
            ciphertext (List[]): _description_
            sk_y (int): functional decryption key for vector y
            y (List[y]): vector y
            limit (int): the upper bound for the inner product result

        Returns:
            int: inner product of x and y or None if the inner product was not found
            within the limit
        """
        ct_0 = ciphertext['ct0']
        ct = ciphertext['ct']
        y = reduce_vector_mod(y, self.p)
        t = [ct[i] ** y[i] for i in range(len(ct))]
        product = np.prod(t)
        intermediate = product / (ct_0 ** sk_y)

        pi = get_int(intermediate)
        g = get_int(self.g)

        inner_prod = dummy_discrete_log(g, pi, self.p, limit)
        return inner_prod
