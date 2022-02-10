from charm.toolbox.integergroup import IntegerGroup
from helpers import generateGroup, getNbitPrime, getRandomZpElement
import numpy as np

class DDH_PK():
    
    def __init__(self, G=None, p=None, g=None) -> None:
        self.G = G
        self.g = g
        self.p = p

    def setUp(self, security_parameter, message_length):
        (self.G, self.p, self.g) = generateGroup(security_parameter)
        s = [getRandomZpElement(self.p) for i in range(message_length)]
        h = [self.g ** s[i] for i in range(message_length)]
        (mpk, msk) = (h, s)
        return (mpk, msk)

    def encrypt(self, mpk, x):
        r = getRandomZpElement(self.p)
        ct_0 = self.g ** r
        h = mpk
        ct = [(h[i] ** r)*(self.g ** x[i]) for i in range(len(x))]
        return (ct_0, ct)
    
    def deriveFunctionalKey(self, msk, y):
        s = msk
        return np.inner(s, y)
        
    def decrypt(self, mpk, Ct, sk_y):
        ct_0 = Ct[0]
        ct = Ct[1]
        intermediate = np.prod([ct[i] ** y[i] for i in range(len(ct))])/(ct_0 ** sk_y)