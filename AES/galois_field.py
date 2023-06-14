class GF8:
    # Galois field (2^8)
    def __init__(self, key):
        if key & 0xFF != key:
            raise ValueError("GF8 only supports values in the range 0x00 - 0xFF")
        self.key = key

    def __getitem__(self, key):
        return self.key & (1 << key)

    def __add__(self, other):
        return GF8(self.key ^ other.key)

    def __sub__(self, other):
        return GF8(self.key ^ other.key)

    def __mul__(self, other):
        p = 0
        for i in range(8):
            if other[i]:
                p ^= self.key << i
        for i in range(p.bit_length() - 1, 7, -1):
            if p & (1 << i):
                p ^= 0x11B << (i - 8)
        return GF8(p)

    def __pow__(self, power):
        if power == 0:
            return GF8(1)
        elif power == 1:
            return GF8(self.key)
        elif power % 2 == 0:
            return (self * self) ** (power // 2)
        else:
            return self * (self * self) ** (power // 2)

    def __truediv__(self, other):
        return self * other.inv()

    def __mod__(self, other):
        sbl = self.bit_length()
        obl = other.bit_length()
        for i in range(sbl - 1, obl - 2, -1):
            if self[i]:
                self.key ^= other.key << (i - obl + 1)
        return self

    def __xor__(self, other):
        if isinstance(other, int):
            other = GF8(other)
        if isinstance(other, GF8):
            return GF8(self.key ^ other.key)
        raise TypeError(
            "Unsupported operand type(s) for ^: '{}' and '{}'".format(
                type(self).__name__, type(other).__name__
            )
        )

    def __and__(self, other):
        if isinstance(other, GF8):
            return GF8(self.key & other.key)
        elif isinstance(other, int):
            return GF8(self.key & other)
        else:
            raise TypeError("unsupported operand type(s) for &: 'GF8' and '{}'".format(type(other).__name__))

    def __rshift__(self, other):
        if isinstance(other, int):
            return GF8(self.key >> other)
        raise TypeError(
            "Unsupported operand type(s) for >>: '{}' and '{}'".format(
                type(self).__name__, type(other).__name__
            )
        )

    def inv(self):
        # Fermat's little theorem
        return self**254

    def reverse(self):
        # reverse bit order
        return GF8(int("{:08b}".format(self.key)[::-1], 2))

    def bit_length(self):
        return self.key.bit_length()

    def __int__(self):
        return self.key

    def __str__(self):
        return hex(self.key)

    def __repr__(self):
        return str(self)