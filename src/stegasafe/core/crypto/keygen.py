import os
from typing import Union
from cryptography.hazmat.primitives.asymmetric import rsa, x25519, ed25519
from cryptography.hazmat.primitives import serialization
from stegasafe.utils.exceptions import KeyGenerationError

"""
klasse für erstellung eines schlüssels für AES.
da wir AES-128, 192 oder 256 nutzen können, brauchen wir jeweils ein schlüssel in dieser bitlänge.
bei os.urandom muss man durch 8 dividieren, weil die methode erwartet bytes (16, 24, 32), nicht bits
"""

class SymmetricKeyGen:
    @staticmethod
    def generate_aes_key(bit_size: int = 256) -> bytes:
        if bit_size not in [128, 192, 256]:
            # Specific error for unsupported AES bit sizes
            raise KeyGenerationError(
                f"AES key generation failed: {bit_size} is not a supported bit size. Please use 128, 192, or 256 bits.")

        try:
            return os.urandom(bit_size // 8)
        except Exception:
            # Catch-all for unexpected system entropy issues
            raise KeyGenerationError(f"Symmetric key generation failed.")

"""
klasse für erstellung eines RSA/ECC key pairs.
für RSA 1024, 2048, 3072 oder 4096 bit key
für key exchange X25519
für signaturen Ed25519
"""

class AsymmetricKeyGen:

    @staticmethod
    def generate_rsa_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
        if key_size not in [1024, 2048, 3072, 4096]:
            # Specific error for invalid RSA key sizes
            raise KeyGenerationError(
                f"RSA key generation failed: {key_size} bits is not supported. Valid sizes are 1024, 2048, 3072, or 4096.")

        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )
            return private_key
        except Exception:
            raise KeyGenerationError(f"RSA key generation failed")

    @staticmethod
    def generate_ecc_key(algorithm: str = "X25519") -> Union[x25519.X25519PrivateKey, ed25519.Ed25519PrivateKey]:
        algorithm_upper = algorithm.upper()

        try:
            if algorithm_upper == "X25519":
                return x25519.X25519PrivateKey.generate()
            elif algorithm_upper == "ED25519":
                return ed25519.Ed25519PrivateKey.generate()
            else:
                # Specific error for unknown ECC algorithms
                raise KeyGenerationError(f"ECC key generation failed: Unsupported algorithm '{algorithm}'.")
        except KeyGenerationError:
            # Re-raise error
            raise
        except Exception:
            # Generic wrapper for library-level failures
            raise KeyGenerationError(f"ECC key generation failed")


"""
hilfsklasse um key in bytes umzuwandeln für vault
"""


class KeySerializer:

    @staticmethod
    def private_key_to_pem(private_key, password: str = None) -> bytes:
        try:
            if password:
                encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
            else:
                encryption_algorithm = serialization.NoEncryption()

            return private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            )
        except Exception:
            # Formatting errors are wrapped to provide clear UI feedback
            raise KeyGenerationError(f"Failed to serialize private key to PEM format.")

    @staticmethod
    def public_key_to_pem(public_key) -> bytes:
        try:
            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        except Exception:
            raise KeyGenerationError(f"Failed to serialize public key to PEM format.")