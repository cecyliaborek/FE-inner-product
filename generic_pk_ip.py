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
from charm.toolbox.eccurve import prime192v2
from charm.toolbox.ecgroup import ECGroup
from charm.schemes.pkenc.pkenc_elgamal85 import ElGamal

class ElGamalInnerProduct:

    def setUp(self, security_parameter: int, vector_length: int):
        groupObj = ECGroup(prime192v2)
        el = ElGamal(groupObj)
        master_public_key = {}
        master_secret_key = {}
        for i in range(vector_length):
            master_public_key[i], master_secret_key[i] = el.keygen(secparam=security_parameter)
        return (master_public_key, master_secret_key)