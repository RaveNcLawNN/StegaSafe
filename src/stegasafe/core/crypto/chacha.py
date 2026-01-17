from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from .primitives import CryptoPackage, IVGenerator


class ChaChaCipher:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("ChaCha20 key must be exactly 32 bytes.")
        self.key = key
        self.algo = ChaCha20Poly1305(key)

    def encrypt(self, data: bytes) -> bytes:
        nonce = IVGenerator.generate("CHACHA20")

        ciphertext_with_tag = self.algo.encrypt(nonce, data, None)

        tag = ciphertext_with_tag[-16:]
        ciphertext = ciphertext_with_tag[:-16]

        package = CryptoPackage(ciphertext=ciphertext, iv=nonce, tag=tag)
        return package.to_bytes("CHACHA20")

    def decrypt(self, raw_data: bytes) -> bytes:
        package = CryptoPackage.from_bytes(raw_data, "CHACHA20")

        data_to_decrypt = package.ciphertext + package.tag

        try:
            return self.algo.decrypt(package.iv, data_to_decrypt, None)
        except Exception:
            raise ValueError("ChaCha20 Decryption failed (Invalid Tag or Key)")