import pytest

from weakkey import is_key_safe

THRESHOLD = 126


def test_weak():
    # this is a key with only 93 bits security from the paper:
    unsafe_key = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xEC\x69\x7A\xA8'
    assert not is_key_safe(unsafe_key)
    assert not is_key_safe(unsafe_key, threshold=THRESHOLD)
    assert not is_key_safe(unsafe_key, threshold=94)
    assert is_key_safe(unsafe_key, threshold=93)


def test_strong():
    # most keys should be strong
    safe_key = b'\xfe\xde\xec\x12\x34\x56\x78\x00\xaa\xbb\xcc\xdd\xee\xff\x42\x23'
    assert is_key_safe(safe_key)
    assert is_key_safe(safe_key, threshold=THRESHOLD)


def test_invalid_threshold():
    key = b'\42' * 16
    with pytest.raises(AssertionError):
        is_key_safe(key, threshold=0)
    with pytest.raises(AssertionError):
        is_key_safe(key, threshold=129)
