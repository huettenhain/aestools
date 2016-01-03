"""
Test for weak AES GCM keys.
"""

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

    The weakness described in the paper is against the authentication in GCM.
    The strength of the authentication tag of GCM is at most 128 bit, because
    the tag is a 128 bit value computed inside a finite field of size 2^128.
    The size of the AES key has no influence on this, it is inherent to GCM.
    See also the wikipedia page on GCM, second paragraph:
    https://en.wikipedia.org/wiki/Galois/Counter_Mode#Security
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
