import pytest

from Crypto.Util.number import bytes_to_long, long_to_bytes

from aestools.checkkey import \
    gf_2_128_mul as ffmul,   \
    gf_2_128_exp as ffexp,   \
    gf_2_128_order as fford
from os import urandom


def test_field_axioms():
    for k in range(1000):
        a, b, c = (bytes_to_long(urandom(16)) for k in range(3))
        assert ffmul(a, ffmul(b, c)) == ffmul(ffmul(a, b), c)
        assert ffmul(a, b) == ffmul(b, a)
        assert ffmul(a, b ^ c) == ffmul(a, b) ^ ffmul(a, c)
        assert ffmul(a, 1 << 127) == a


def test_order_reduction():
    factors = (3, 5, 17, 257, 641, 65537, 274177, 6700417, 67280421310721)
    a = bytes_to_long(urandom(16))
    for factor in factors:
        if fford(a) % factor == 0:
            assert fford(ffexp(a, factor)) % factor != 0


def test_order_correct():
    for k in range(10):
        a = bytes_to_long(urandom(16))
        g = fford(a)
        assert ffexp(a, g) == (1 << 127)
    assert fford(1 << 127) == 1
