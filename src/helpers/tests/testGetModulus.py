from charm.toolbox.integergroup import IntegerGroup

from src.helpers.helpers import get_modulus

group = IntegerGroup()
group.paramgen(1024)

g = group.randomGen()

print(g)
print()


mod = get_modulus(g)

print(mod)
print(type(mod))