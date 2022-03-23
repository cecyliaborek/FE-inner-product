from charm.toolbox.integergroup import IntegerGroup

group = IntegerGroup()
group.paramgen(8)

g = group.randomGen()

num = b'123'

e = group.encode(num)
print(e)

d = group.decode(e)
print(d.decode('utf-8'))
