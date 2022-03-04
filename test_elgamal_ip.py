from elgamal_ip import ElGamalInnerProduct


s = ElGamalInnerProduct()

pk, sk = s.setUp(1024, 4)


print(sk[1]['x'])
print(type(sk[1]['x']))

g = pk[0]['g']

print(g)
print(type(g))


y = [1, 1, 1, 1]


key = s.getFunctionalKey(sk, y)

print(key)
print(type(key))


x = [1, 2, 3, 4]

ct = s.encrypt(pk, x)