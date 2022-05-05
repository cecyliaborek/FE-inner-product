"""
Michel Abdalla et al. generic functional encryption inner product scheme based on additive
    ElGamal

| From: Abdalla, Michel et al. “Simple Functional Encryption Schemes for Inner Products.” 
| Published in: Public-Key Cryptography -- PKC 2015. Berlin, Heidelberg: 
|               Springer Berlin Heidelberg, 2015. 733–751. Web.
| DOI: 10.1007/978-3-662-46447-2_33

* type:         functional encryption (public key)
* setting:      SchnorrGroup mod p
* assumption:   DDH

:Authors:       Cecylia Borek
:Date:          03/2022

Note: Because to recover the final result of inner product discrete logarithm calculation is needed, the inner product
should lie within a reasonable limit, otherwise the calculation may take too long.
"""
from charm.toolbox.integergroup import IntegerGroupQ, integer
from typing import List, Dict, Tuple
from src.helpers.additive_elgamal import AdditiveElGamal, ElGamalCipher
from src.helpers.helpers import reduce_vector_mod, get_int
from src.errors.wrong_vector_for_provided_key import WrongVectorForProvidedKey
import charm
import numpy as np

IntegerGroupElement = charm.core.math.integer.integer
ElGamalKey = Dict[str, IntegerGroupElement]

debug = True

# the common parameters for underlying additive ElGamal
p = integer(
        148829018183496626261556856344710600327516732500226144177322012998064772051982752493460332138204351040296264880017943408846937646702376203733370973197019636813306480144595809796154634625021213611577190781215296823124523899584781302512549499802030946698512327294159881907114777803654670044046376468983244647367)
q = integer(
    74414509091748313130778428172355300163758366250113072088661006499032386025991376246730166069102175520148132440008971704423468823351188101866685486598509818406653240072297904898077317312510606805788595390607648411562261949792390651256274749901015473349256163647079940953557388901827335022023188234491622323683)
elgamal_group = IntegerGroupQ()
elgamal = AdditiveElGamal(elgamal_group, p, q)
elgamal_params = {"group": elgamal_group, "p": int(p)}


def set_up(security_parameter: int, vector_length: int) -> Tuple[List[ElGamalKey], List[ElGamalKey]]:
    """
    Generates master public and secret key
    Args:
        security_parameter: security parameter for generating underlying Elgamal's keys
        vector_length: supported length of vectors

    Returns:
        Tuple[List[ElGamalKey], List[ElGamalKey]]: master public key and master secret key
    """

    master_public_key = [None] * vector_length
    master_secret_key = [None] * vector_length
    for i in range(vector_length):
        (master_public_key[i], master_secret_key[i]) = elgamal.keygen(secparam=security_parameter)
    return master_public_key, master_secret_key


def get_functional_key(msk: List[ElGamalKey], y: List[int]) -> int:
    """Derives functional key for calculating inner product with vector y

    Args:
        msk (List[ElGamalKey]): master secret key
        y (List[int]): vector for which the functional key should be calculated

    Raises:
        WrongVectorSizeError: if the vector y is longer than the supported vector length

    Returns:
        int: Functional key corresponding to vector y
    """
    if len(y) > len(msk):
        raise WrongVectorForProvidedKey(f'Vector {y} too long for the configured FE')
    y = reduce_vector_mod(y, elgamal_params['p'])
    key = 0
    for i in range(len(y)):
        key += get_int(msk[i]['x']) * y[i]
    return key


def encrypt(mpk: List[ElGamalKey], x: List[int]) -> dict:
    """Encrypts integer vector x

    Args:
        mpk (List[ElGamalKey]): master public key
        x (List[int]): integer vector to be encrypted

    Raises:
        WrongVectorSizeError: if the provided vector is longer than supported vector length

    Returns:
        Dict[str, List[IntegerGroupElement]]: ciphertext corresponding to vector x
    """
    if len(x) > len(mpk):
        raise WrongVectorForProvidedKey(f'Vector {x} too long for the configured FE')
    r = elgamal_params['group'].random()
    ct_0 = mpk[0]['g'] ** r
    x = reduce_vector_mod(x, elgamal_params['p'])
    ct = [elgamal.encrypt(mpk[i], x[i], r) for i in range(len(x))]
    ciphertext = {'ct0': ct_0, 'ct': ct}
    return ciphertext


def decrypt(mpk: List[ElGamalKey],
            ciphertext: dict,
            sk_y: int,
            y: List[int],
            limit: int) -> int:
    """Returns inner product of vector y and vector x encrypted in ciphertext

    Args:
        mpk (List[ElGamalKey]): master public key
        ciphertext (dict): ciphertext encrypting vector x
        sk_y (int): functional decryption key for vector y
        y (List[int]): vector y
        limit (int): upper bound up until which the inner product should be searched for

    Returns:
        int: inner product of x and y or None if the inner product was not found
        within the limit
    """
    ct_0 = ciphertext['ct0']
    ct = ciphertext['ct']
    y = reduce_vector_mod(y, elgamal_params['p'])

    c1 = ct_0
    c2 = np.product([ct[i]['c2'] ** y[i] for i in range(len(ct))])
    sk = {'x': sk_y}  # constructing the secret key in a form acceptable by ElGamal
    pk = mpk[0]  # public key same for all i's

    # constructing ciphertext for additive ElGamal
    c = ElGamalCipher({'c1': c1, 'c2': c2})
    return elgamal.decrypt(pk, sk, c, limit)
