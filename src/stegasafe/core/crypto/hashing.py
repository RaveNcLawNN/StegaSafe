import hashlib

from stegasafe.utils import read_bytes


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """
    Return hex digest of data using the selected algorithm (default sha256).
    """
    h = hashlib.new(algorithm)
    h.update(data)
    return h.hexdigest()


def hash_file(path: str, algorithm: str = "sha256") -> str:
    """
    Read a file and return its hash as a hex string.
    """
    data = read_bytes(path)
    return hash_bytes(data, algorithm=algorithm)


def verify_file_hash(path: str, expected_hex: str, algorithm: str = "sha256") -> bool:
    """
    Compute file hash and compare with a user-provided reference hash (hex).
    Ignores case and surrounding whitespace,
    """
    actual = hash_file(path, algorithm=algorithm)
    return actual == expected_hex.strip().lower()