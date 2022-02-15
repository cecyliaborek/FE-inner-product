from helpers import encryptInExponent, generateGroup, getRandomZpElement
import numpy as np

class DDH_PK():
    
    def __init__(self, group=None, p=None, g=None) -> None:
        self.group = group
        self.g = g
        self.p = p

    def setUp(self, security_parameter, message_length):
        (self.group, self.p, self.g) = generateGroup(security_parameter)
        s = [getRandomZpElement(self.p) for i in range(message_length)]
        h = [encryptInExponent(self.g, s[i], self.p) for i in range(message_length)]
        (mpk, msk) = (h, s)
        return (mpk, msk)

    def encrypt(self, mpk, x):
        r = getRandomZpElement(self.p)
        ct_0 = encryptInExponent(self.g, r, self.p)
        h = mpk
        ct = [(h[i] ** r)*(encryptInExponent(self.g, x[i], self.p)) for i in range(len(x))]
        return (ct_0, ct)
    
    def deriveFunctionalKey(self, msk, y):
        s = msk
        return np.inner(s, y)
        
    def decrypt(self, mpk, ciphertext, sk_y, y):
        ct_0 = ciphertext[0]
        ct = ciphertext[1]
        intermediate = np.prod([ct[i] ** y[i] for i in range(len(ct))])/(ct_0 ** sk_y)
        # calculate discrete log