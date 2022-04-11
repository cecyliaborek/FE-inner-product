import unittest
import numpy as np
from src.helpers.matrix import Matrix


class TestMatrix(unittest.TestCase):

    def setUp(self) -> None:
        self.A = Matrix((2, 3), 4)
        self.B = Matrix((3, 4), 2)
        self.A_np = np.full((2, 3), 4)
        self.B_np = np.full((3, 4), 2)

    def test_multiplication(self):
        c = self.A * self.B
        c_np = np.dot(self.A_np, self.B_np)
        print(c)
        print(c_np)


if __name__ == '__main__':
    unittest.main()
