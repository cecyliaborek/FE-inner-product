import Crypto.Util.number
from charm.toolbox.integergroup import IntegerGroup
import secrets

def getNbitPrime(n):
    return Crypto.Util.number.getPrime(n, randfunc=Crypto.Random.get_random_bytes)

def generateGroup(sec_param):
    group = IntegerGroup()
    group.paramgen(sec_param)
    g = group.randomGen()
    p = group.groupOrder()
    return (group, p, g)

def getRandomZpElement(p):
    return secrets.randbelow(p)