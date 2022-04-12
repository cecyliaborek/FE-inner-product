from src.helpers.incompatible_matrix_dimensions_exception import IncompatibleMatrixDimensionsException


class Matrix:

    def __init__(self, dims: tuple, fill=0):
        self.rows = dims[0]
        self.cols = dims[1]
        self.values = [[fill] * self.cols for _ in range(self.rows)]

    @classmethod
    def from_list(cls, m_list):
        if not isinstance(m_list, list):
            raise ValueError(f"{cls.__qualname__} takes list as argument but {type(m_list)} was provided")
        n = len(m_list)
        if n == 0:
            return cls((0, 0))
        if all(isinstance(elem, int) for elem in m_list):
            matrix = cls((1, n))
            for i in range(n):
                matrix.values[0][i] = m_list[i]
            return matrix
        if all(isinstance(elem, list) for elem in m_list):
            m = len(m_list[0])
            if all(len(elem) == m for elem in m_list):
                matrix = cls((n, m))
                for i in range(n):
                    for j in range(m):
                        matrix.values[i][j] = m_list[i][j]
                return matrix
            raise ValueError(f"Different lengths of rows for provided list {m_list}")
        raise ValueError(f"{cls.__qualname__} takes list of lists or ints as argument but "
                         f"{[type(elem) for elem in m_list]} was provided")

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
        result = Matrix((self.rows, self.cols))
        if isinstance(other, Matrix):
            if self.rows != other.rows or self.cols != other.cols:
                raise IncompatibleMatrixDimensionsException
            for i in range(self.rows):
                for j in range(self.cols):
                    result.values[i][j] = self.values[i][j] * other.values[i][j]
        elif isinstance(other, (int, float)):
            for i in range(self.rows):
                for j in range(self.cols):
                    result.values[i][j] = self.values[i][j] * other
        return result

    def __rmul__(self, other):
        return self.__mul__(other)

    def __matmul__(self, other):
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

    def __rmatmul__(self, other):
        return self.__matmul__(other)

    def __str__(self):
        matrix_str = '['
        first_row = True
        for i in range(self.rows):
            first_col = True
            if first_row:
                matrix_str += '['
                first_row = False
            else:
                matrix_str += '\n ['
            for j in range(self.cols):
                if first_col:
                    matrix_str += str(self.values[i][j])
                    first_col = False
                else:
                    matrix_str += ' ' + str(self.values[i][j])
            matrix_str += ']'
        matrix_str += ']'
        return matrix_str

    def __repr__(self):
        return self.__str__()

    def __mod__(self, other):
        result = Matrix(dims=(self.rows, self.cols))
        if isinstance(other, Matrix):
            if self.rows != other.rows or self.cols != other.cols:
                raise IncompatibleMatrixDimensionsException
            for i in range(self.rows):
                for j in range(self.cols):
                    result.values[i][j] = self.values[i][j] % other.values[i][j]
        elif isinstance(other, (int, float)):
            for i in range(self.rows):
                for j in range(self.cols):
                    result.values[i][j] = self.values[i][j] % other
        return result

    def __setitem__(self, key, value):
        if isinstance(key, tuple):
            i = key[0]
            j = key[1]
            self.values[i][j] = value

    def __getitem__(self, key):
        if isinstance(key, tuple):
            i = key[0]
            j = key[1]
            return self.values[i][j]

    def size(self):
        return self.rows, self.cols

    def multipy_modulo(self, other, mod):
        result = None
        if isinstance(other, Matrix):
            if other.rows != self.cols:
                raise IncompatibleMatrixDimensionsException
            result = Matrix((self.rows, other.cols), fill=0)
            for i in range(self.rows):
                for j in range(other.cols):
                    acc = 0
                    for k in range(self.cols):
                        acc += (self.values[i][k] * other.values[k][j]) % mod
                    result.values[i][j] = acc
        return result

