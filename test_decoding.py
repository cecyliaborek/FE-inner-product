from charm.toolbox.integergroup import IntegerGroup

from helpers import decodeFromGroupElement, encodeAsGroupElement


group = IntegerGroup()
group.paramgen(1024)

g = group.randomGen()

num = 89473

num_encoded = encodeAsGroupElement(num, group)

print(num_encoded)
print(type(num_encoded))


num_decoded = decodeFromGroupElement(num_encoded, group)



print(num_decoded)
print(type(num_decoded))