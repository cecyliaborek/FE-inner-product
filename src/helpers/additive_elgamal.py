'''
Additive El Gamal Public Key Encryption Scheme for the purpose of ElGamal Inner product scheme
Adapted from Charm pkenc_elgamal85 scheme (https://jhuisi.github.io/charm/charm/schemes/pkenc/pkenc_elgamal85.html#pkenc_elgamal85.ElGamalCipher)

| Available from: 
| Notes: 

* type:          encryption (public key)
* setting:       DDH-hard prime order group
* assumption:    DDH

:Authors:        Cecylia Borek
:Date:           3/2022
'''

from charm.toolbox.PKEnc import PKEnc

from src.helpers.helpers import dummyDiscreteLog, getInt, getModulus

debug = False


class ElGamalCipher(dict):
    def __init__(self, ct):
        if type(ct) != dict: assert False, "Not a dictionary!"
        if not set(ct).issubset(['c1', 'c2']): assert False, "'c1','c2' keys not present."
        dict.__init__(self, ct)

    def __add__(self, other):
        if type(other) == int:
            lhs_c1 = dict.__getitem__(self, 'c1')
            lhs_c2 = dict.__getitem__(self, 'c2')
            return ElGamalCipher({'c1': lhs_c1, 'c2': lhs_c2 + other})
        else:
            pass

    def __mul__(self, other):
        if type(other) == int:
            lhs_c1 = dict.__getitem__(self, 'c1')
            lhs_c2 = dict.__getitem__(self, 'c2')
            return ElGamalCipher({'c1': lhs_c1, 'c2': lhs_c2 * other})
        else:
            lhs_c1 = dict.__getitem__(self, 'c1')
            rhs_c1 = dict.__getitem__(other, 'c1')

            lhs_c2 = dict.__getitem__(self, 'c2')
            rhs_c2 = dict.__getitem__(other, 'c2')
            return ElGamalCipher({'c1': lhs_c1 * rhs_c1, 'c2': lhs_c2 * rhs_c2})
        return None


class AdditiveElGamal(PKEnc):
    """Additive ElGamal Scheme allowing for shared randomness for encryption.
    Group generator is an instance variable.

    Args:
        PKEnc (_type_): _description_
    """

    def __init__(self, groupObj, p=0, q=0):
        PKEnc.__init__(self)
        global group
        group = groupObj
        group.p, group.q, group.r = p, q, 2
        self.g = group.randomGen()

    def keygen(self, secparam=1024):
        if group.p == 0 or group.q == 0:
            group.paramgen(secparam)
        # x is private, g is public param
        x = group.random();
        h = self.g ** x
        if debug:
            print('Public parameters...')
            print('h => %s' % h)
            print('g => %s' % self.g)
            print('Secret key...')
            print('x => %s' % x)
        pk = {'g': self.g, 'h': h}
        sk = {'x': x}
        return (pk, sk)

    def encrypt(self, pk, x, r):
        c1 = pk['g'] ** r
        s = pk['h'] ** r
        # exponential ElGamal
        m = pk['g'] ** x
        c2 = m * s
        return ElGamalCipher({'c1': c1, 'c2': c2})

    def decrypt(self, pk, sk, c):
        s = c['c1'] ** sk['x']
        m = c['c2'] * (s ** -1)
        M = m % group.p
        if debug: print('m => %s' % m)
        if debug: print('dec M => %s' % M)
        x = dummyDiscreteLog(getInt(pk['g']), M, getModulus(pk['g']), 200)
        return x
