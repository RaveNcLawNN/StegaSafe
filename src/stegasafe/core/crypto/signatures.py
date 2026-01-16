"""
Digital signature functionality for StegaSafe.

Uses Ed25519 for creating and verifying digital signatures.
Ed25519 is fast, secure, and produces 64-byte signatures.
"""

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from src.stegasafe.utils import read_bytes
from stegasafe.utils.exceptions import SignatureError


def create_signature(data: bytes, private_key_pem: bytes) -> bytes:
    """
    Create a digital signature for data using a private key.

    Args:
        data: The data to sign (bytes)
        private_key_pem: Private key in PEM format (bytes)

    Returns:
        Signature bytes (64 bytes for Ed25519)

    Raises:
        ValueError: If the private key is invalid or wrong type
    """
    try:
        # Load private key from PEM format
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None  # No password protection for now (can add later)
        )

        # Make sure it's an Ed25519 key
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            # Specific error for wrong key type
            raise SignatureError("The selected key is not a valid Ed25519 Private Key.")

        # Sign the data
        signature = private_key.sign(data)
        return signature

    except SignatureError:
        # Re-raise our custom domain error
        raise
    except Exception as e:
        raise SignatureError(f"Failed to create digital signature: {str(e)}")


def verify_signature(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """
    Verify a digital signature.

    Args:
        data: The original data that was signed
        signature: The signature bytes to verify (64 bytes for Ed25519)
        public_key_pem: Public key in PEM format (bytes)

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Load public key from PEM format
        public_key = serialization.load_pem_public_key(public_key_pem)

        # Make sure it's an Ed25519 key
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            raise SignatureError("The provided key is not a valid Ed25519 Public Key.")

        # Verify signature (raises InvalidSignature if wrong)
        public_key.verify(signature, data)
        return True

    except InvalidSignature:
        # Signature doesn't match the data
        return False
    except SignatureError:
        # Re-raise domain error for the UI
        raise
    except Exception:
        # Catch-all for corruption or wrong formats
        raise SignatureError("Signature verification failed due to corrupted data or an invalid key format.")


def sign_file(file_path: str, private_key_pem: bytes) -> bytes:
    """
    Sign a file and return the signature.

    Args:
        file_path: Path to the file to sign
        private_key_pem: Private key in PEM format (bytes)

    Returns:
        Signature bytes (64 bytes for Ed25519)
    """
    data = read_bytes(file_path)
    return create_signature(data, private_key_pem)


def verify_file_signature(file_path: str, signature: bytes, public_key_pem: bytes) -> bool:
    """
    Verify a file's signature.

    Args:
        file_path: Path to the file that was signed
        signature: The signature bytes to verify
        public_key_pem: Public key in PEM format (bytes)

    Returns:
        True if signature is valid, False otherwise
    """
    data = read_bytes(file_path)
    return verify_signature(data, signature, public_key_pem)