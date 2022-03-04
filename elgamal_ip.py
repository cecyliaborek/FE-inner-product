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

:Authors: Cecylia Borek
:Date: 03/2022
"""
from charm.toolbox.integergroup import IntegerGroupQ, integer
from charm.schemes.pkenc.pkenc_elgamal85 import ElGamal
from typing import List, Dict
from helpers import getInt, getModulus, reduceVectorMod, intToBytes
from wrong_vector_size_error import WrongVectorSizeError
import charm

IntegerGroupElement = charm.core.math.integer.integer

class ElGamalInnerProduct:

    def setUp(self, security_parameter: int, vector_length: int):
        p = integer(148829018183496626261556856344710600327516732500226144177322012998064772051982752493460332138204351040296264880017943408846937646702376203733370973197019636813306480144595809796154634625021213611577190781215296823124523899584781302512549499802030946698512327294159881907114777803654670044046376468983244647367)
        q = integer(74414509091748313130778428172355300163758366250113072088661006499032386025991376246730166069102175520148132440008971704423468823351188101866685486598509818406653240072297904898077317312510606805788595390607648411562261949792390651256274749901015473349256163647079940953557388901827335022023188234491622323683)
        elgamal_group = IntegerGroupQ()
        self.elgamal = ElGamal(elgamal_group, p, q)
        master_public_key = [None] * vector_length
        master_secret_key = [None] * vector_length
        for i in range(vector_length):
            (master_public_key[i], master_secret_key[i]) = self.elgamal.keygen(secparam=security_parameter)

        self.elgamal_params = {}
        self.elgamal_params['group'] = elgamal_group
        self.elgamal_params['g'] = master_public_key[0]['g']
        self.elgamal_params['q'] = getModulus(self.elgamal_params['g'])

        # generator to make elgamal additively homomorphic

        return (master_public_key, master_secret_key)

    def getFunctionalKey(self, msk, y: List[int]) -> int:
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
            raise WrongVectorSizeError(f'Vector {y} too long for the configured FE')
        y = reduceVectorMod(y, self.elgamal_params['q'])
        key = 0
        for i in range(len(y)):
            key += getInt(msk[i]['x']) * y[i]
        return key

    def encrypt(self, mpk: List[Dict[str, IntegerGroupElement]], x: List[int]) -> Dict[str, List[IntegerGroupElement]]:
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
            raise WrongVectorSizeError(f'Vector {x} too long for the configured FE')
        r = self.elgamal_params['group'].random()
        ct_0 = self.elgamal_params['g'] ** r
        x = reduceVectorMod(x, self.elgamal_params['q'])
        ct = [self.elgamal.encrypt(mpk[i], intToBytes(x[i])) for i in range(len(x))]
        ciphertext = {'ct0': ct_0, 'ct': ct}
        return ciphertext

    def decrypt(self, mpk, ciphertext: Dict[str, IntegerGroupElement], sk_y: int, y: List[int]) -> int:
        """Returns inner product of vector y and vector x encrypted in ciphertext

        Args:
            mpk (_type_): _description_
            ciphertext (List[]): _description_
            sk_y (int): functional decryption key for vector y
            y (List[y]): vector y

        Returns:
            int: inner product of x and y or None if the inner product was not found
            within the limit
        """
        ct_0 = ciphertext['ct0']
        ct = ciphertext['ct']
        y = reduceVectorMod(y, self.elgamal_params['q'])
        
