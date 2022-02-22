from charm.toolbox.integergroup import IntegerGroup

from helpers import getInt, getModulus

group = IntegerGroup()
group.paramgen(1024)

g = group.randomGen()

print(g)
print()


i = getInt(g)

print(i)
print(type(i))