import os
from typing import Union
from cryptography.hazmat.primitives.asymmetric import rsa, x25519, ed25519
from cryptography.hazmat.primitives import serialization

"""
klasse für erstellung eines schlüssels für AES.
da wir AES-128, 192 oder 256 nutzen können, brauchen wir jeweils ein schlüssel in dieser bitlänge.
bei os.urandom muss man durch 8 dividieren, weil die methode erwartet bytes (16, 24, 32), nicht bits
"""

class SymmetricKeyGen:
    @staticmethod
    def generate_aes_key(bit_size: int = 256) -> bytes:
        if bit_size not in [128, 192, 256]:
            raise ValueError("erlaubt nur 128, 192, 256")
        return os.urandom(bit_size // 8)

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
            raise ValueError("RSA key_size muss 1024, 2048, 3072 oder 4096 sein")

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        return private_key

    @staticmethod
    def generate_ecc_key(algorithm: str = "X25519") -> Union[x25519.X25519PrivateKey, ed25519.Ed25519PrivateKey]:
        if algorithm.upper() == "X25519":
            return x25519.X25519PrivateKey.generate()
        elif algorithm.upper() == "ED25519":
            return ed25519.Ed25519PrivateKey.generate()
        else:
            raise ValueError("unknown algorithm")

"""
hilfsklasse um key in bytes umzuwandeln für vault
"""

class KeySerializer:

    @staticmethod
    def private_key_to_pem(private_key, password: str = None) -> bytes:
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption_algorithm = serialization.NoEncryption()

        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )

    @staticmethod
    def public_key_to_pem(public_key) -> bytes:
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

