import pytest

from binascii import hexlify, unhexlify

from aestools.checkkey import is_key_safe, bit_strength_gcm_auth

THRESHOLD = 126

KEYS_STRENGTHS = [
    # keys and strengths as mentioned in the paper
    ('000000000000000000000000EC697AA8', 93),   # note: keep a weak key at idx 0
    ('00000000000000000000000000000002', 126),
    ('00000000000000000000000000000003', 125),
    ('000000000000000000000000243E8B40', 96),
    ('0000000000000000000000003748CFCE', 96),
    ('00000000000000000000000042873CC8', 93),
    # an arbitrary strong key
    ('fedeec1234567800aabbccddeeff4223', 127),  # note: keep strong key at idx -1
]
KEYS_STRENGTHS = [(unhexlify(k), s) for k, s in KEYS_STRENGTHS]

WEAK, STRONG = 0, -1  # index in KEYS_STRENGTHS


def test_weak():
    unsafe_key, strength = KEYS_STRENGTHS[WEAK]
    assert not is_key_safe(unsafe_key)
    assert not is_key_safe(unsafe_key, threshold=THRESHOLD)
    assert not is_key_safe(unsafe_key, threshold=strength+1)
    assert is_key_safe(unsafe_key, threshold=strength)


def test_strong():
    safe_key, _ = KEYS_STRENGTHS[STRONG]
    assert is_key_safe(safe_key)
    assert is_key_safe(safe_key, threshold=THRESHOLD)


def test_invalid_threshold():
    key, _ = KEYS_STRENGTHS[STRONG]
    with pytest.raises(AssertionError):
        is_key_safe(key, threshold=0)
    with pytest.raises(AssertionError):
        is_key_safe(key, threshold=129)


def test_strength():
    for key, strength in KEYS_STRENGTHS:
        assert bit_strength_gcm_auth(key) == strength
