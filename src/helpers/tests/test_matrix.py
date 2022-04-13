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
        c = self.A @ self.B
        c_np = np.dot(self.A_np, self.B_np)
        print(c)
        print(c_np)

    def test_init_from_list(self):
        y = [1, 2, 3, 4]
        matrix = Matrix.from_list(y)
        self.assertIsInstance(matrix, Matrix)
        self.assertEqual(matrix[0, 0], 1)
        self.assertEqual(matrix[0, 1], 2)
        self.assertEqual(matrix[0, 2], 3)
        self.assertEqual(matrix[0, 3], 4)
        print(matrix)

    def test_transpose(self):
        a = Matrix.from_list([[1, 2], [3, 4], [5, 6]])
        self.assertEqual(a.transpose(), Matrix.from_list([[1, 3, 5], [2, 4, 6]]))


if __name__ == '__main__':
    unittest.main()
