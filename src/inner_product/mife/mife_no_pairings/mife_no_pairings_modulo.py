"""
Abdalla, Michel et al. Multi-input functional encryption schemes without pairings for inner product over integers
    modulo L



| From:         Abdalla, Michel et al. “Multi-Input Functional Encryption for Inner Products: Function-Hiding
                Realizations and Constructions Without Pairings.”
| Published in: Advances in Cryptology – CRYPTO 2018. Cham: Springer International Publishing, 2018. 597–627. Web.
| DOI:          10.1007/978-3-319-96884-1_20

* type:         private key multi-input functional encryption
* setting:
* assumption:

:Authors:       Cecylia Borek
:Date:          03/2022

Note: Because to recover the final result of inner product discrete logarithm calculation is needed, the inner product
should lie within a reasonable limit, otherwise the calculation may take too long.
"""
from src.errors.wrong_vector_for_provided_key import WrongVectorForProvidedKey
from src.inner_product.mife.mife_no_pairings.function_families import MultiInputInnerProductZl
import src.inner_product.mife.mife_no_pairings.one_time_secure_mife
import src.inner_product.single_input_fe.elgamal_ip.elgamal_ip
from typing import List


class MSK:
    def __init__(self, ot_mife_key, fe_msks):
        self.ot_mife_key = ot_mife_key
        self.fe_msks = fe_msks

    @property
    def ot_mife_key(self):
        return self._ot_mife_key

    @ot_mife_key.setter
    def ot_mife_key(self, ot_mife_key):
        self._ot_mife_key = ot_mife_key

    @property
    def fe_msks(self):
        return self._fe_msks

    @fe_msks.setter
    def fe_msks(self, fe_msks):
        if type(fe_msks) != list:
            raise ValueError("fe_msks should be a list of single-input fe's private keys")
        self._fe_msks = fe_msks


class MPK:
    def __init__(self, ot_mife_modulus: int, fe_mpks: list):
        self.fe_mpks = fe_mpks
        self.ot_mife_modulus = ot_mife_modulus

    @property
    def fe_mpks(self):
        return self._fe_mpks

    @property
    def ot_mife_modulus(self):
        return self._ot_mife_modulus

    @ot_mife_modulus.setter
    def ot_mife_modulus(self, ot_mife_modulus):
        if type(ot_mife_modulus) != int:
            raise ValueError("ot_mife_modulus should be an integer representing modulus of one time secure mife")
        self._ot_mife_modulus = ot_mife_modulus

    @fe_mpks.setter
    def fe_mpks(self, fe_mpks):
        if type(fe_mpks) != list:
            raise ValueError("fe_mpks should be a list of single-input fe's public keys")
        self._fe_mpks = fe_mpks


class FunctionalKey:
    def __init__(self, sk: list, z):
        self.sk = sk
        self.z = z

    @property
    def sk(self):
        return self._sk

    @sk.setter
    def sk(self, sk):
        if type(sk) != list:
            raise ValueError("sk should be a list of single-input fe's functional keys")
        self._sk = sk

    @property
    def z(self):
        return self._z

    @z.setter
    def z(self, z):
        self._z = z


# selection of underlying schemes
ot_mife = src.inner_product.mife.mife_no_pairings.one_time_secure_mife
single_input_fe = src.inner_product.single_input_fe.elgamal_ip.elgamal_ip


def set_up(func_descr: MultiInputInnerProductZl, security_param: int) -> (MPK, MSK):
    """

    Args:
        func_descr: description of a function family for inner product this scheme should support
        security_param: security parameter

    Returns:
        (master public key, master secret key)
    """
    vector_len = func_descr.n
    inner_vector_len = func_descr.m
    ot_mife_key, ot_mife_modulus = ot_mife.set_up(func_descr, security_param)
    fe_mpks = [None] * vector_len
    fe_msks = [None] * vector_len
    for i in range(vector_len):
        fe_mpks[i], fe_msks[i] = single_input_fe.set_up(security_param, inner_vector_len)
    msk = MSK(ot_mife_key, fe_msks)
    mpk = MPK(ot_mife_modulus, fe_mpks)
    return mpk, msk


def encrypt(mpk: MPK, msk: MSK, i: int, x_i: List[int]) -> dict:
    """ Encrypts i-th element of integer vector

    Args:
        mpk: master public key
        msk: master secret key
        i: index of the element to be encrypted in the vector
        x_i: value of the i-th element of the vector

    Returns:
        ciphertext encrypting i-th element of the vector
    """
    w_i = ot_mife.encrypt(msk.ot_mife_key, mpk.ot_mife_modulus, i, x_i)
    return single_input_fe.encrypt(mpk.fe_mpks[i], w_i)


def get_functional_key(mpk: MPK, msk: MSK, y: List[List[int]]) -> FunctionalKey:
    """Derives functional key for calculating inner product with integer vector y

    Args:
        mpk: master public key
        msk: master secret key
        y: integer vector for which the functional key should be calculated

    Returns:
        functional key corresponding to vector y
    """
    if len(y) != len(msk.fe_msks):
        raise WrongVectorForProvidedKey(
            f"The length of the provided vector {y} doesn't match the length of the key list {msk.fe_msks}"
        )
    sk = [single_input_fe.get_functional_key(msk.fe_msks[i], y[i]) for i in range(len(y))]
    z = ot_mife.get_functional_key(msk.ot_mife_key, mpk.ot_mife_modulus, y)
    return FunctionalKey(sk, z)


def decrypt(mpk: MPK, func_key: FunctionalKey, ciphertext, y: List[List[int]], limit: int) -> int:
    """Recovers the inner product of x and y from x's ciphertext, y's functional key and y

    Args:
        mpk: master public key
        func_key: functional key for vector y
        ciphertext: ciphertext encrypting all elements of vector x
        y: vector y
        limit: limit within the final inner product should lie

    Returns:
        the inner product of x and y if it lies within the limit, otherwise None
    """
    d = []
    for i in range(len(ciphertext)):
        d.append(single_input_fe.decrypt(mpk.fe_mpks[i], ciphertext[i], func_key.sk[i], y[i], limit))
    return (sum(d) - func_key.z) % mpk.ot_mife_modulus
