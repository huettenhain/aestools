import pytest

from aestools.checkkey import is_key_safe
from aestools.safekey import get_safe_key


def test_get_safe_key():
    for threshold in 125, 126, 127, :
        for length in 128, 256:
            key1 = get_safe_key(length, threshold=threshold)
            key2 = get_safe_key(length, threshold=threshold)
            assert key1 != key2
            assert len(key1) == len(key2) == length // 8
            assert is_key_safe(key1, threshold=threshold)
            assert is_key_safe(key2, threshold=threshold)


def test_get_safe_key_not_found():
    with pytest.raises(Exception):
        get_safe_key(128, max_tries=0)


def test_get_safe_key_invalid():
    with pytest.raises(AssertionError):
        get_safe_key(0)
    with pytest.raises(AssertionError):
        get_safe_key(512)

