__author__ = 'ateng'


class Bytes(bytes):

    def _pad(self, other):
        s = len(self)
        o = len(other)
        if s == o:
            return zip(self, other)
        if s > o:
            return zip(self, (other * (s // o)) + (other[0:s%o]))
        if o > s:
            return zip((self * (o // s)) + (self[0:o%s]), other)

    def __xor__(self, other):
        return Bytes([i1 ^ i2 for (i1, i2) in self._pad(other)])
