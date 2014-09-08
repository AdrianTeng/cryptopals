from itertools import cycle, islice
 
 
class Bytes(bytes):
    def __new__(cls, value):
        # We can't override __init__ as bytes is immutable.
        # See https://docs.python.org/3/reference/datamodel.html#object.__new__
        if isinstance(value, str):
            value = map(ord, value)
 
        return super().__new__(cls, value)
 
    def _zip_longest(self, other):
        """Zip this byte sequence with another. If they're not the same
        length, repeat the items from the shorter sequence.
 
        If you just want to zero-pad the shorter byte sequence, you
        can do this instead:
 
        >>> itertools.zip_longest(self, other, fillvallue=0)
 
        """
        length = max(len(self), len(other))
        # We can't use
        # >>> zip(cycle(self), cycle(other))[:length]
        # here because zip doesn't return a list in Python 3.
        return islice(zip(cycle(self), cycle(other)), length)
 
    def __xor__(self, other):
        return Bytes([i1 ^ i2 for (i1, i2) in self._zip_longest(other)])