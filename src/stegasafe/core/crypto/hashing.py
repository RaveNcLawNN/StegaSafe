import hashlib

from stegasafe.utils import read_bytes
from stegasafe.utils.exceptions import IntegrityError


def _normalize_algorithm_name(algorithm: str) -> str:
    """
    Convert user-friendly algorithm name to hashlib-compatible name.
    
    Examples:
    - "SHA-256" -> "sha256"
    - "SHA-512/224" -> "sha512_224"
    - "SHA3-256" -> "sha3_256"
    - "SHAKE128" -> "shake_128"
    """
    # Convert to lowercase and handle special cases
    algo_lower = algorithm.lower().strip()
    
    # Handle SHA-512 variants (slash becomes underscore)
    algo_lower = algo_lower.replace("/", "_")
    
    # Remove all dashes
    algo_lower = algo_lower.replace("-", "_")
    
    # Handle SHAKE algorithms - they need special treatment
    if algo_lower.startswith("shake_"):
        return algo_lower  # Already in correct format
    
    # For standard algorithms, remove underscores if any
    # (e.g., "sha3_256" stays as is, but "sha_256" becomes "sha256")
    if algo_lower.startswith("sha") and "_" in algo_lower:
        # Keep underscore for sha3_* and sha512_* variants
        if algo_lower.startswith("sha3_") or algo_lower.startswith("sha512_"):
            return algo_lower
        # Remove underscore for others (e.g., "sha_256" -> "sha256")
        return algo_lower.replace("_", "")
    
    return algo_lower


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """
    Return hex digest of data using the selected algorithm (default sha256).
    
    Supports all FIPS 180-4 (SHA-1, SHA-2) and FIPS 202 (SHA-3) algorithms.
    For SHAKE algorithms, uses standard output lengths:
    - SHAKE128: 256 bits (32 bytes) output
    - SHAKE256: 512 bits (64 bytes) output
    """
    algo_normalized = _normalize_algorithm_name(algorithm)
    
    # Handle SHAKE algorithms (extendable output functions)
    if algo_normalized == "shake_128":
        h = hashlib.shake_128()
        h.update(data)
        # SHAKE128: use 256 bits (32 bytes) = 64 hex characters
        return h.hexdigest(32)
    elif algo_normalized == "shake_256":
        h = hashlib.shake_256()
        h.update(data)
        # SHAKE256: use 512 bits (64 bytes) = 128 hex characters
        return h.hexdigest(64)
    else:
        # Standard hash algorithms
        try:
            h = hashlib.new(algo_normalized)
        except ValueError:
            raise IntegrityError(
                f"Unsupported hashing algorithm: {algorithm}. "
                "Please use a standard FIPS 180-4 or FIPS 202 algorithm."
            )
        h.update(data)
        return h.hexdigest()


def hash_file(path: str, algorithm: str = "sha256") -> str:
    """
    Read a file and return its hash as a hex string.
    
    Supports all FIPS 180-4 (SHA-1, SHA-2) and FIPS 202 (SHA-3) algorithms.
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
    Ignores case and surrounding whitespace.
    
    Supports all FIPS 180-4 (SHA-1, SHA-2) and FIPS 202 (SHA-3) algorithms.
    """
    # The errors from hash_file will bubble up through here to the UI decorator
    actual = hash_file(path, algorithm=algorithm)
    return actual == expected_hex.strip().lower()
