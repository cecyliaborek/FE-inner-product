from charm.toolbox.integergroup import IntegerGroup

from helpers.helpers import getModulus

group = IntegerGroup()
group.paramgen(1024)

g = group.randomGen()

print(g)
print()


mod = getModulus(g)

print(mod)
print(type(mod))