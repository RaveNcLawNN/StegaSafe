from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag
from .primitives import CryptoPackage, IVGenerator, PaddingManager
from stegasafe.utils.exceptions import CryptographyError

class AESCipher:

    def __init__(self, key: bytes):
        if len(key) not in [16, 24, 32]:
            raise CryptographyError(f"Invalid key length ({len(key)} bytes). AES keys must be 16, 24, or 32 bytes.")
        self.key = key

    def _get_cipher_instance(self, mode: str, iv: bytes):
        if mode == "GCM":
            return modes.GCM(iv)
        elif mode == "CBC":
            return modes.CBC(iv)
        elif mode == "CTR":
            return modes.CTR(iv)
        elif mode == "CFB":
            return modes.CFB(iv)
        elif mode == "OFB":
            return modes.OFB(iv)
        elif mode == "ECB":
            return modes.ECB()
        else:
            raise CryptographyError(f"Unsupported AES mode: {mode}")

    def encrypt(self, data: bytes, mode: str = "GCM") -> bytes:
        try:
            if mode in ["CBC", "ECB"]:
                data = PaddingManager.pad_data(data)

            iv = IVGenerator.generate(mode)

            mode_instance = self._get_cipher_instance(mode, iv)

            cipher = Cipher(algorithms.AES(self.key), mode_instance)
            encryptor = cipher.encryptor()

            ciphertext = encryptor.update(data) + encryptor.finalize()

            tag = encryptor.tag if mode == "GCM" else None

            package = CryptoPackage(ciphertext=ciphertext, tag=tag, iv=iv)
            return package.to_bytes(mode)
        except Exception as e:
            raise CryptographyError(f"Encryption failed: {str(e)}")

    def decrypt(self, raw_data: bytes, mode: str = "GCM") -> bytes:
        package = CryptoPackage.from_bytes(raw_data, mode)

        if mode == "GCM":
            mode_instance = modes.GCM(package.iv, package.tag)
        else:
            mode_instance = self._get_cipher_instance(mode, package.iv)

        cipher = Cipher(algorithms.AES(self.key), mode_instance)
        decryptor = cipher.decryptor()

        try:
            plaintext = decryptor.update(package.ciphertext) + decryptor.finalize()
        except InvalidTag:
            raise CryptographyError("Decryption failed: Invalid authentication tag. The key might be wrong or the data tampered.")
        except Exception as e:
            raise CryptographyError(f"Decryption failed: {str(e)}")

        if mode in ["CBC", "ECB"]:
            try:
                plaintext = PaddingManager.unpad_data(plaintext)
            except Exception:
                raise CryptographyError("Decryption failed: Padding error. This usually indicates an incorrect key.")

        return plaintext