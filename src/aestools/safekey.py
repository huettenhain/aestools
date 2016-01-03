"""
Generate a key that is not weak.
"""

import os

from .checkkey import is_key_safe, THRESHOLD_DEFAULT


def get_safe_key(bits, threshold=THRESHOLD_DEFAULT, max_tries=100):
    assert bits in (128, 256)
    assert max_tries >= 0  # 0 only makes sense for tests
    bytelength = bits // 8
    safe = False
    i = 0
    while not safe:
        i += 1
        if i > max_tries:
            raise Exception("could not find safe key")
        key = os.urandom(bytelength)
        safe = is_key_safe(key, threshold)
    return key
