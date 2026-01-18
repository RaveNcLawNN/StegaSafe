from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from .primitives import CryptoPackage, IVGenerator
from stegasafe.utils.exceptions import CryptographyError

class ChaChaCipher:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise CryptographyError("ChaCha20 key must be exactly 32 bytes (256 bits) Choose a correct AES key.")
        self.key = key
        self.algo = ChaCha20Poly1305(key)

    def encrypt(self, data: bytes) -> bytes:
        nonce = IVGenerator.generate("CHACHA20")  # 12 Bytes
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
            raise CryptographyError("ChaCha20-Poly1305 Decryption failed (Invalid Tag or Key)")


class ChaChaStreamCipher:

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise CryptographyError("ChaCha20 key must be exactly 256 bits long (32 bytes).")
        self.key = key

    def encrypt(self, data: bytes) -> bytes:
        nonce = IVGenerator.generate("CHACHA20-STREAM")

        algorithm = algorithms.ChaCha20(self.key, nonce)
        cipher = Cipher(algorithm, mode=None)  # Stream ciphers have no mode like CBC
        encryptor = cipher.encryptor()

        ciphertext = encryptor.update(data)

        package = CryptoPackage(ciphertext=ciphertext, iv=nonce, tag=None)
        return package.to_bytes("CHACHA20-STREAM")

    def decrypt(self, raw_data: bytes) -> bytes:
        package = CryptoPackage.from_bytes(raw_data, "CHACHA20-STREAM")

        algorithm = algorithms.ChaCha20(self.key, package.iv)
        cipher = Cipher(algorithm, mode=None)
        decryptor = cipher.decryptor()

        return decryptor.update(package.ciphertext)