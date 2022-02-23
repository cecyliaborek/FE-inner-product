"""
Michel Abdalla et al. DDH based simple functional encryption inner product scheme

* type: functional encryption (public key)
* setting: integer
* assumption: DDH

| From: Abdalla, Michel et al. “Simple Functional Encryption Schemes for Inner Products.” 
| Published in: Public-Key Cryptography -- PKC 2015. Berlin, Heidelberg: 
|               Springer Berlin Heidelberg, 2015. 733–751. Web.
| DOI: 10.1007/978-3-662-46447-2_33
| Notes:


:Authors: Cecylia Borek
:Date: 02/2022
"""
from helpers import encodeAsGroupElement, encodeVectorToGroupElements, generateGroup, getInt, getModulus, innerProduct
import numpy as np
import logging

logger = logging.getLogger(__name__)
FORMAT = "[%(filename)s: %(funcName)17s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

class DDH_PK():
    
    def __init__(self, group=None, g=None) -> None:
        self.group = group
        self.g = g

    def setUp(self, security_parameter, message_length):
        (self.group, self.g, self.p) = generateGroup(security_parameter)
        logger.debug('g: ' + str(self.g))
        s = [self.group.random() for _ in range(message_length)]
        logger.debug('s:' + str(s))
        h = [self.g ** s[i] for i in range(message_length)]
        logger.debug('h: ' + str(h))
        mpk = {'h': h}
        msk = {'s': s}
        return (mpk, msk)

    def encrypt(self, mpk, x):
        r = self.group.random()
        logger.debug('r: ' + str(r))
        ct_0 = self.g ** r
        logger.debug('ct0: ' + str(ct_0))
        h = mpk['h']
        x = encodeVectorToGroupElements(x, self.group)
        logger.debug('x encoded: ' + str(x))
        ct = [(h[i] ** r) * (self.g ** x[i]) for i in range(len(x))]
        logger.debug('ct: ' + str(ct))
        ciphertext = {'ct0': ct_0, 'ct': ct}
        return ciphertext
    
    def getFunctionalKey(self, msk, y):
        s = msk['s']
        y = encodeVectorToGroupElements(y, self.group)
        logger.debug('y encoded: ' + str(y))
        return innerProduct(s, y, self.group)
        
    def decrypt(self, mpk, ciphertext, sk_y, y):
        ct_0 = ciphertext['ct0']
        ct = ciphertext['ct']
        t = [ct[i] ** y[i] for i in range(len(ct))]
        logger.debug('t: '+ str(t))
        product = np.prod(t)
        logger.debug('product of t:'+ str(product))
        intermediate = product/(ct_0 ** sk_y)
        logger.debug('ct0/sky: ' + str(ct_0 ** sk_y))
        logger.debug('product of t/ct0^ksy: ' + str(intermediate))

        pi = getInt(intermediate)
        
        p = getModulus(self.g)
        g = getInt(self.g)

        inner_prod = dummyDiscreteLog(g, pi, p, 200)
        return inner_prod