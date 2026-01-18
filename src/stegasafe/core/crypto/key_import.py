"""
Key import and validation functionality for StegaSafe.

Supports importing symmetric (AES) and asymmetric (RSA, Ed25519, X25519) keys
from external files in various formats.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, x25519
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from stegasafe.utils.exceptions import ValidationError, KeyGenerationError


def validate_symmetric_key(key_bytes: bytes) -> tuple[str, int]:
    """
    Validate a symmetric key and return algorithm and bit size.
    
    Args:
        key_bytes: Raw key bytes
        
    Returns:
        Tuple of (algorithm, bit_size)
        
    Raises:
        ValidationError: If key length is invalid
    """
    key_len = len(key_bytes)
    
    if key_len == 16:
        return ("AES", 128)
    elif key_len == 24:
        return ("AES", 192)
    elif key_len == 32:
        return ("AES", 256)
    else:
        raise ValidationError(
            f"Invalid symmetric key length: {key_len} bytes. "
            "AES keys must be 16, 24, or 32 bytes (128, 192, or 256 bits)."
        )


def validate_asymmetric_key_pem(pem_bytes: bytes) -> tuple[str, str, int | None]:
    """
    Validate an asymmetric key in PEM format and return algorithm, role, and bit size.
    
    Args:
        pem_bytes: Key in PEM format (bytes)
        
    Returns:
        Tuple of (algorithm, role, bit_size)
        - algorithm: "RSA", "Ed25519", or "X25519"
        - role: "private" or "public"
        - bit_size: For RSA keys, the key size in bits. None for ECC keys.
        
    Raises:
        ValidationError: If key format is invalid or unsupported
    """
    try:
        # Try to load as private key first
        try:
            private_key = serialization.load_pem_private_key(pem_bytes, password=None)
            
            if isinstance(private_key, RSAPrivateKey):
                bit_size = private_key.key_size
                return ("RSA", "private", bit_size)
            elif isinstance(private_key, Ed25519PrivateKey):
                return ("Ed25519", "private", None)
            elif isinstance(private_key, X25519PrivateKey):
                return ("X25519", "private", None)
            else:
                raise ValidationError(f"Unsupported private key type: {type(private_key).__name__}")
                
        except (ValueError, TypeError):
            # Not a private key, try public key
            try:
                public_key = serialization.load_pem_public_key(pem_bytes)
                
                if isinstance(public_key, RSAPublicKey):
                    bit_size = public_key.key_size
                    return ("RSA", "public", bit_size)
                elif isinstance(public_key, Ed25519PublicKey):
                    return ("Ed25519", "public", None)
                elif isinstance(public_key, X25519PublicKey):
                    return ("X25519", "public", None)
                else:
                    raise ValidationError(f"Unsupported public key type: {type(public_key).__name__}")
                    
            except (ValueError, TypeError) as e:
                raise ValidationError(f"Failed to parse PEM key. The file does not appear to be a valid RSA, Ed25519, or X25519 key.")
                
    except Exception as e:
        raise ValidationError(f"Key validation failed.")


def detect_and_validate_key(file_contents: bytes) -> tuple[str, bytes, str, str, int | None]:
    """
    Detect key format and validate it.
    
    Args:
        file_contents: Raw file contents (bytes)
        
    Returns:
        Tuple of (key_kind, key_bytes, algorithm, role, bit_size)
        - key_kind: "symmetric" or "asymmetric"
        - key_bytes: Validated key bytes (ready to store)
        - algorithm: "AES", "RSA", "Ed25519", or "X25519"
        - role: "private" or "public" (for asymmetric), None for symmetric
        - bit_size: Key size in bits (for RSA/AES), None for ECC
        
    Raises:
        ValidationError: If key format is invalid
    """
    # Check if it's PEM format (starts with -----BEGIN)
    pem_start = b"-----BEGIN"
    
    if file_contents.strip().startswith(pem_start):
        # It's a PEM-encoded asymmetric key
        algorithm, role, bit_size = validate_asymmetric_key_pem(file_contents)
        return ("asymmetric", file_contents, algorithm, role, bit_size)
    else:
        # Try to parse as symmetric key (raw bytes or hex)
        key_bytes = None
        
        # Try hex encoding first (if file looks like hex text)
        try:
            hex_str = file_contents.decode('utf-8').strip()
            # Check if it's purely hexadecimal (allow spaces/newlines)
            hex_chars_only = ''.join(hex_str.split())
            if len(hex_chars_only) > 0 and all(c in '0123456789abcdefABCDEF' for c in hex_chars_only):
                # Must be even length for valid hex
                if len(hex_chars_only) % 2 == 0:
                    key_bytes = bytes.fromhex(hex_chars_only)
        except (ValueError, UnicodeDecodeError):
            pass
        
        # If hex parsing failed, use raw bytes
        if key_bytes is None:
            key_bytes = file_contents
        
        # Validate symmetric key
        algorithm, bit_size = validate_symmetric_key(key_bytes)
        return ("symmetric", key_bytes, algorithm, None, bit_size)
