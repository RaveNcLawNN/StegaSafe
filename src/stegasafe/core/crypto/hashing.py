import hashlib

from stegasafe.utils import read_bytes
from stegasafe.utils.exceptions import IntegrityError


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """
    Return hex digest of data using the selected algorithm (default sha256).
    """
    try:
        h = hashlib.new(algorithm)
    except ValueError:
        # Handling unsupported or invalid algorithm names
        raise IntegrityError(f"Unsupported hashing algorithm: {algorithm}. "
                             "Please use a standard algorithm (e.g., sha256, sha512, or sha3_256).")

    h.update(data)
    return h.hexdigest()


def hash_file(path: str, algorithm: str = "sha256") -> str:
    """
    Read a file and return its hash as a hex string.
    """
    try:
        data = read_bytes(path)
        return hash_bytes(data, algorithm=algorithm)
    except IntegrityError:
        # Re-raise domain error
        raise
    except Exception as e:
        # Catch-all for file access or unexpected issues during the hashing process
        raise IntegrityError(f"Failed to compute hash for the selected file: {str(e)}")


def verify_file_hash(path: str, expected_hex: str, algorithm: str = "sha256") -> bool:
    """
    Compute file hash and compare with a user-provided reference hash (hex).
    Ignores case and surrounding whitespace,
    """
    # The errors from hash_file will bubble up through here to the UI decorator
    actual = hash_file(path, algorithm=algorithm)
    return actual == expected_hex.strip().lower()