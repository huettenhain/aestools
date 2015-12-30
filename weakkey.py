"""
Test for weak AES keys when used in Galois Counter Mode with a block size
of 128 bits, as explained in the paper "Cycling Attacks on GCM, GHASH and 
Other Polynomial MACs and Hashes": https://eprint.iacr.org/2011/202.pdf

This snippet requires the pycrypto package:
pip install pycrypto
"""

from __future__ import print_function

import sys
from binascii import hexlify, unhexlify

from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Random import random

# Utility Functions ############################################################

def gf_2_128_mul(x, y):
    assert x < (1 << 128)
    assert y < (1 << 128)
    res = 0
    for i in range(127, -1, -1):
        res ^= x * ((y >> i) & 1)  # branchless
        x = (x >> 1) ^ ((x & 1) * 0xE1000000000000000000000000000000)
    assert res < (1 << 128)
    return res


def gf_2_128_exp(x, n):
    if n == 0:
        return 1
    q, r = divmod(n, 2)
    if r == 1:
        return gf_2_128_mul(x, gf_2_128_exp(gf_2_128_mul(x, x), q))
    else:
        return                 gf_2_128_exp(gf_2_128_mul(x, x), q)


def gf_2_128_order(x):
    factors = (3, 5, 17, 257, 641, 65537, 274177, 6700417, 67280421310721)
    order = 1
    for factor in factors:
        n = ((1 << 128) - 1) // factor
        if gf_2_128_exp(x, n) != 1:
            order *= factor
    return order


# ##############################################################################
    
THRESHOLD_DEFAULT = 126

def is_key_safe(key, threshold=THRESHOLD_DEFAULT):
    """
    Expects an AES key as a binary string and a threshold which should be a 
    number between 1 and 128. It roughly measures the number of bits of security
    that the key is required to have in GCM.
    """
    # Threshold should be a number between 1 and 128. 
    assert threshold >= 1
    assert threshold <= 128
    c = AES.new(key, AES.MODE_ECB)
    h = bytes_to_long(c.encrypt("\x00" * 16))
    group_order = gf_2_128_order(h)
    return group_order >= (1 << threshold)


def selftest():
    unsafe_key = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xEC\x69\x7A\xA8'
    assert not is_key_safe(unsafe_key), "self-test failed with unsafe key"
    safe_key = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
    assert is_key_safe(safe_key), "self-test failed with safe key"


if __name__ == '__main__':
    if len(sys.argv) == 2:
        selftest()
        key = unhexlify(sys.argv[1].encode('ascii'))
        assert len(key) in (16, 32)
        assert isinstance(key, bytes)
        safe = is_key_safe(key)
        print("%s is safe: %r" % (hexlify(key).decode('ascii'), safe))
    else:
        print("Usage: python weakkey.py 00112233445566778899aabbccddeeff")
