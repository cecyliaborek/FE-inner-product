from charm.toolbox.integergroup import integer, IntegerGroup

from helpers.helpers import getInt, getModulus
import unittest

class TestHelpers(unittest.TestCase):

    def testGetInt(self):
        p = integer(123456789)
        print(p)
        i = getInt(p)

        self.assertEqual(123456789, i)

    def testGetMod(self):
        group = IntegerGroup()
        group.paramgen(1024)
        g = group.randomGen()

        mod = getModulus



if __name__=="__main__":
    unittest.main()