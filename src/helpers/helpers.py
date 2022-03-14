from charm.toolbox.integergroup import IntegerGroup
import charm
from typing import List
from charm.core.math.integer import getMod, toInt

IntegerGroupElement = charm.core.math.integer.integer

def generateGroup(sec_param):
    """Generates a Schnorr mod p where p is a prime of
    bitsize equal to sec_param

    Args:
        sec_param (int): security parameter, bitsize of p

    Returns:
        Tuple(): _description_
    """
    group = IntegerGroup()
    group.paramgen(sec_param)
    g = group.randomGen()
    return (group, g)

def innerProduct(a: List[IntegerGroupElement], b: List[int]) -> int:
    n = min(len(a), len(b))
    inner = 0
    for i in range(n):
        inner += getInt(a[i]) * b[i]
    return inner

def decodeVectorFromGroupElements(vector: List[IntegerGroupElement], group: IntegerGroup) -> List[int]:
    decoded_vector = []
    for i in range(len(vector)):
        decoded_vector.append(bytesToInt(group.decode(vector[i])))
    return decoded_vector

def decodeFromGroupElement(element: IntegerGroupElement, group: IntegerGroup) -> int:
    return bytesToInt(group.decode(element))

def encodeVectorToGroupElements(vector: List[int], group: IntegerGroup) -> List[IntegerGroupElement]:
    encoded_vector = []
    for i in range(len(vector)):
        encoded_vector.append(encodeAsGroupElement(vector[i], group))
    return encoded_vector

def encodeAsGroupElement(x: int, group: IntegerGroup) -> IntegerGroupElement:
    return group.encode(intToBytes(x))

def intToBytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')

def bytesToInt(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, byteorder='big')


def getModulus(element: IntegerGroupElement) -> int:
    """From a mod N returns N

    Args:
        element (IntegerGroupElement): Group element of form a mod N

    Returns:
        int: Modulus of modular expression, a mod N -> N
    """
    mod = int(getMod(element))
    return mod

def getInt(element: IntegerGroupElement) -> int:
    """From a mod N returns a

    Args:
        element (IntegerGroupElement): Group element of form a mod N

    Returns:
        int: Integer part of modular expression, a mod N -> a
    """
    return int(toInt(element))
    

def product(vector: List[int]) -> int:
    prod = 1
    for element in vector:
        prod = prod * element
    return prod


def dummyDiscreteLog(a: int, b: int, mod: int, limit: int) -> int:
    """Calculates discrete log of b in the base of a modulo mod, provided the
    result is smaller than limit. Otherwise returns None

    Args:
        a (int): base of logarithm
        b (int): number from which the logarithm is calculated
        mod (int): modulus of logarithm 
        limit (int): limit within which the result should lie

    Returns:
        int: result of logarithm or None if the result was not found withn the limit
    """
    for i in range(limit) :
        if pow(a, i, mod) == b:
            return i
    return None

def reduceVectorMod(vector: List[int], mod: int) -> List[int]:
    """Reduces all elements of a vector modulo mod

    Args:
        vector (List[int]): list representation of vetor
        mod (int): modulus

    Returns:
        List[int]: vector with reduced elements
    """
    reduced = []
    for i in range(len(vector)):
        reduced.append(vector[i] % mod)
    return reduced