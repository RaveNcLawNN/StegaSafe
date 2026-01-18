from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
# Wir brauchen das Serialization Modul auch hier oben für die Konstanten
from cryptography.hazmat.primitives import serialization
from .aes import AESCipher
from .primitives import CryptoPackage, IVGenerator

class HybridCipher:
    """
    Implements ECC Hybrid Encryption (S5/S6).
    Uses X25519 for Key Exchange and AES-GCM for Payload Encryption.
    """

    @staticmethod
    def encrypt(data: bytes, recipient_public_key_pem: bytes) -> bytes:
        # 1. Load Recipient Pub Key
        peer_public_key = load_pem_public_key(recipient_public_key_pem)
        if not isinstance(peer_public_key, x25519.X25519PublicKey):
            raise ValueError("Hybrid encryption requires an X25519 Public Key")

        # 2. Generate Ephemeral Key Pair
        ephemeral_private = x25519.X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()

        # 3. Perform ECDH (Shared Secret)
        shared_secret = ephemeral_private.exchange(peer_public_key)

        # 4. Derive Symmetric Key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'stegasafe-hybrid-v1'
        ).derive(shared_secret)

        # 5. Encrypt Payload (AES-GCM)
        aes = AESCipher(derived_key)
        aes_output_bytes = aes.encrypt(data, mode="GCM")

        # 6. Repackage
        inner_pkg = CryptoPackage.from_bytes(aes_output_bytes, "GCM")

        # Key in Raw Bytes (32 Bytes) konvertieren
        ephemeral_pub_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        final_pkg = CryptoPackage(
            ciphertext=inner_pkg.ciphertext,
            iv=inner_pkg.iv,
            tag=inner_pkg.tag,
            ephemeral_public_key=ephemeral_pub_bytes
        )

        return final_pkg.to_bytes("HYBRID")

    @staticmethod
    def decrypt(raw_data: bytes, recipient_private_key_pem: bytes, password: str = None) -> bytes:
        # (Der Rest deiner decrypt Methode war bereits korrekt)
        # 1. Load Private Key
        priv_key = load_pem_private_key(recipient_private_key_pem, password=password.encode() if password else None)
        if not isinstance(priv_key, x25519.X25519PrivateKey):
            raise ValueError("Hybrid decryption requires an X25519 Private Key")

        # 2. Parse Package (Extract Ephemeral Key)
        package = CryptoPackage.from_bytes(raw_data, "HYBRID")

        if not package.ephemeral_public_key or len(package.ephemeral_public_key) != 32:
            raise ValueError("Invalid Hybrid Package: Missing Ephemeral Key")

        ephemeral_pub_key = x25519.X25519PublicKey.from_public_bytes(package.ephemeral_public_key)

        # 3. Reconstruct Shared Secret
        shared_secret = priv_key.exchange(ephemeral_pub_key)

        # 4. Derive Symmetric Key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'stegasafe-hybrid-v1'
        ).derive(shared_secret)

        # 5. Decrypt Payload
        aes = AESCipher(derived_key)

        temp_pkg = CryptoPackage(ciphertext=package.ciphertext, iv=package.iv, tag=package.tag)
        raw_aes_input = temp_pkg.to_bytes("GCM")

        return aes.decrypt(raw_aes_input, mode="GCM")