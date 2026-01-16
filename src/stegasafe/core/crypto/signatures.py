"""
Digital signature functionality for StegaSafe.

Supports both Ed25519 and RSA signatures.
- Ed25519: Fast, secure, produces 64-byte signatures
- RSA: Uses PSS padding with SHA-256, supports 1024, 2048, 3072, 4096 bit keys
"""

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

from stegasafe.utils import read_bytes
from stegasafe.utils.exceptions import SignatureError


def create_signature(data: bytes, private_key_pem: bytes) -> bytes:
    """
    Create a digital signature for data using a private key.
    Supports both Ed25519 and RSA keys (auto-detected).

    Args:
        data: The data to sign (bytes)
        private_key_pem: Private key in PEM format (bytes)

    Returns:
        Signature bytes (64 bytes for Ed25519, variable for RSA)

    Raises:
        SignatureError: If the private key is invalid or unsupported type
    """
    try:
        # Load private key from PEM format
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None  # No password protection for now (can add later)
        )

        # Route to appropriate signing method based on key type
        if isinstance(private_key, ed25519.Ed25519PrivateKey):
            # Ed25519: Direct signing, no padding needed
            signature = private_key.sign(data)
            return signature
        
        elif isinstance(private_key, rsa.RSAPrivateKey):
            # RSA: Use PSS padding with SHA-256
            signature = private_key.sign(
                data,
                padding=PSS(
                    mgf=MGF1(hashes.SHA256()),
                    salt_length=PSS.MAX_LENGTH
                ),
                algorithm=hashes.SHA256()
            )
            return signature
        
        else:
            raise SignatureError(
                f"Unsupported key type for signing. "
                f"Only Ed25519 and RSA keys are supported. "
                f"Found: {type(private_key).__name__}"
            )

    except SignatureError:
        # Re-raise our custom domain error
        raise
    except Exception as e:
        raise SignatureError(f"Failed to create digital signature: {str(e)}")


def verify_signature(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """
    Verify a digital signature.
    Supports both Ed25519 and RSA signatures (auto-detected).

    Args:
        data: The original data that was signed
        signature: The signature bytes to verify
        public_key_pem: Public key in PEM format (bytes)

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Load public key from PEM format
        public_key = serialization.load_pem_public_key(public_key_pem)

        # Route to appropriate verification method based on key type
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            # Ed25519: Direct verification, no padding needed
            public_key.verify(signature, data)
            return True
        
        elif isinstance(public_key, rsa.RSAPublicKey):
            # RSA: Use PSS padding with SHA-256 (must match signing)
            public_key.verify(
                signature,
                data,
                padding=PSS(
                    mgf=MGF1(hashes.SHA256()),
                    salt_length=PSS.MAX_LENGTH
                ),
                algorithm=hashes.SHA256()
            )
            return True
        
        else:
            raise SignatureError(
                f"Unsupported key type for verification. "
                f"Only Ed25519 and RSA keys are supported. "
                f"Found: {type(public_key).__name__}"
            )

    except InvalidSignature:
        # Signature doesn't match the data
        return False
    except SignatureError:
        # Re-raise domain error for the UI
        raise
    except Exception as e:
        # Catch-all for corruption or wrong formats
        raise SignatureError(f"Signature verification failed: {str(e)}")


def sign_file(file_path: str, private_key_pem: bytes) -> bytes:
    """
    Sign a file and return the signature.
    Supports both Ed25519 and RSA keys.

    Args:
        file_path: Path to the file to sign
        private_key_pem: Private key in PEM format (bytes)

    Returns:
        Signature bytes (64 bytes for Ed25519, variable for RSA)
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