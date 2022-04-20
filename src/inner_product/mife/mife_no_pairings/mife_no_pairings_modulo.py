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
"""
from src.errors.wrong_vector_for_provided_key import WrongVectorForProvidedKey
from src.inner_product.mife.mife_no_pairings.function_families import MultiInputInnerProductZl
import src.inner_product.mife.mife_no_pairings.one_time_secure_mife
from src.inner_product.single_input_fe.elgamal_ip.elgamal_ip import ElGamalInnerProductFE


class MSK:
    def __init__(self, ot_mife_key, fe_msks):
        self.ot_mife_key = ot_mife_key
        self.fe_msks = fe_msks

    @property
    def ot_mife_key(self):
        return self._ot_mife_key

    @ot_mife_key.setter
    def ot_mife_key(self, ot_mife_key):
        # todo: check if instance of ot mife key
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
    def __init__(self, fe_mpks: list):
        if type(fe_mpks) != list:
            assert False, "No list of single-input fe's public keys provided"
        self.fe_mpks = fe_mpks

    @property
    def fe_mpks(self):
        return self._fe_mpks

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
        # todo: check if instance of ot mife func key
        self._z = z

ot_mife = src.inner_product.mife.mife_no_pairings.one_time_secure_mife
single_input_fe = ElGamalInnerProductFE()


def set_up(func_descr: MultiInputInnerProductZl, security_param: int) -> (MPK, MSK):
    vector_len = func_descr.n
    inner_vector_len = func_descr.m
    modulus = func_descr.L
    ot_mife_key = ot_mife.set_up(func_descr, security_param)
    fe_mpks = [None] * vector_len
    fe_msks = [None] * vector_len
    for i in range(vector_len):
        fe_mpks[i], fe_msks[i] = single_input_fe.setUp(security_param, inner_vector_len)
    msk = MSK(ot_mife_key, fe_msks)
    mpk = MPK(fe_mpks)
    return mpk, msk


def encrypt(mpk: MPK, msk: MSK, i, x_i):
    w_i = ot_mife.encrypt(msk.ot_mife_key, i, x_i)
    return single_input_fe.encrypt(mpk.fe_mpks[i], w_i)


def get_functional_key(msk: MSK, y):
    if len(y) != len(msk.fe_msks):
        raise WrongVectorForProvidedKey(
            f"The length of the provided vector {y} doesn't match the length of the key list {msk.fe_msks}"
        )
    sk = [single_input_fe.getFunctionalKey(msk.fe_msks[i], y[i]) for i in range(len(y))]
    z = ot_mife.get_functional_key(msk.ot_mife_key, y)
    return FunctionalKey(sk, z)


def decrypt(mpk: MPK, func_key: FunctionalKey, ciphertext, y):
    d = []
    for i in range(len(ciphertext)):
        d.append(single_input_fe.decrypt(mpk.fe_mpks[i], ciphertext[i], func_key.sk[i], y[i]))
    return (sum(d) - func_key.z) % modulus