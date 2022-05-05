class MultiInputInnerProductZl:
    """A description of function family for inner product modulo L

    """

    def __init__(self, L, n, m):
        """

        Args:
            L: modulus
            n: outer vector length
            m: inner vectors lengths
        """
        self.L = L
        self.m = m
        self.n = n


class MultiInputBoundedNormInnerProductZ:
    """A description of function family for bounded norm inner product

    """

    def __init__(self, n, m, X, Y):
        """

        Args:
            n: outer vector length
            m: inner vectors lengths
            X: upper bound for integer elements of vectors to be encrypted
            Y: upper bound for integer elements of vectors for which keys are generated
        """
        self.n = n
        self.m = m
        self.X = X
        self.Y = Y
