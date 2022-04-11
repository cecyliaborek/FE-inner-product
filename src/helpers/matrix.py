from src.helpers.incompatible_matrix_dimensions_exception import IncompatibleMatrixDimensionsException


class Matrix:

    def __init__(self, dims: tuple, fill):
        self.rows = dims[0]
        self.cols = dims[1]
        self.values = [[fill] * self.cols for _ in range(self.rows)]

    def __add__(self, other):
        result = Matrix(dims=(self.rows, self.cols), fill=0)
        if isinstance(other, Matrix):
            if other.rows != self.rows or other.cols != self.cols:
                raise IncompatibleMatrixDimensionsException
            for i in range(self.rows):
                for j in range(self.cols):
                    result.values[i][j] = self.values[i][j] + other.values[i][j]
        elif isinstance(other, int):
            for i in range(self.rows):
                for j in range(self.cols):
                    result.values[i][j] = self.values[i][j] + other

        return result

    def __mul__(self, other):
        result = None
        if isinstance(other, Matrix):
            if other.rows != self.cols:
                raise IncompatibleMatrixDimensionsException
            result = Matrix((self.rows, other.cols), fill=0)
            for i in range(self.rows):
                for j in range(other.cols):
                    acc = 0
                    for k in range(self.cols):
                        acc += self.values[i][k] * other.values[k][j]
                    result.values[i][j] = acc
        return result

    def __str__(self):
        matrix_str = '['
        for i in range(self.rows):
            matrix_str += '['
            for j in range(self.cols):
                matrix_str += str(self.values[i][j]) + ' '
            matrix_str += ']\n'
        matrix_str += ']'
        return matrix_str
