from charm.toolbox.integergroup import IntegerGroup

from helpers import decodeFromGroupElement, encodeAsGroupElement


group = IntegerGroup()
group.paramgen(8)

g = group.randomGen()

num = 123

num_encoded = encodeAsGroupElement(num, group)
print(type(num_encoded), ': ', num_encoded)

num_decoded = decodeFromGroupElement(num_encoded, group)
print(type(num_decoded), ': ', num_decoded)