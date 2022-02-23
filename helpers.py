import charm
from charm.toolbox.integergroup import IntegerGroup
from typing import List
from charm.core.math.integer import getMod, toInt
from sympy import true

IntegerGroupElement = charm.core.math.integer.integer

def generateGroup(sec_param):
    group = IntegerGroup()
    group.paramgen(sec_param)
    g = group.randomGen()
    p = group.p
    return (group, g, p)

def innerProduct(a, b):
    n = min(len(a), len(b))
    inner = 0
    for i in range(n):
        inner = (a[i]) * (b[i])
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
