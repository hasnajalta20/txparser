import pytest
from txparser.compactsize import read_compact_size, write_compact_size

CASES = [(0, 1), (252, 1), (253, 3), (65535, 3), (65536, 5), (2**32 - 1, 5), (2**32, 9)]


@pytest.mark.parametrize("value,length", CASES)
def test_roundtrip(value, length):
    encoded = write_compact_size(value)
    assert len(encoded) == length
    assert read_compact_size(encoded) == (value, length)


def test_offset():
    data = b"\xaa\xbb" + write_compact_size(300)
    assert read_compact_size(data, 2) == (300, 5)


def test_truncated():
    with pytest.raises(ValueError):
        read_compact_size(b"\xfd\x01")
