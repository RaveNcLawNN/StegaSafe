from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag
from .primitives import CryptoPackage, IVGenerator, PaddingManager

class AESCipher:

    def __init__(self, key: bytes):
        # initialisiert die klasse mit einem schlüssel
        if len(key) not in [16, 24, 32]:
            raise ValueError("false schlüssellänge")
        self.key = key

    def _get_cipher_instance(self, mode: str, iv: bytes):
        # hilfsmethode: erstellt das passende mode-objekt für encryption
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
            raise ValueError("falscher mode")

    def encrypt(self, data: bytes, mode: str = "GCM") -> bytes:
        # encrypted daten - padding, iv, encrypt, cryptopackage

        # padding - nur für CBC & ECB weil fixe blockgrößen
        if mode in ["CBC", "ECB"]:
            data = PaddingManager.pad_data(data)

        # iv/nonce
        iv = IVGenerator.generate(mode)

        mode_instance = self._get_cipher_instance(mode, iv)

        cipher = Cipher(algorithms.AES(self.key), mode_instance)
        encryptor = cipher.encryptor()

        # encryption
        ciphertext = encryptor.update(data) + encryptor.finalize()

        # speichern tag (nur bei GCM)
        tag = encryptor.tag if mode == "GCM" else None

        # verpacken alles in cryptopackage
        package = CryptoPackage(ciphertext=ciphertext, tag=tag, iv=iv)
        return package.to_bytes(mode)

    def decrypt(self, raw_data: bytes, mode: str = "GCM") -> bytes:
        # decrypted daten - cryptopackage öffnen, decrypt, padding entfernen

        # slicen cryptopackage in iv, ciphertext und tag
        package = CryptoPackage.from_bytes(raw_data, mode)

        if mode == "GCM":
            # übergeben und prüfen tag bei GCM
            mode_instance = modes.GCM(package.iv, package.tag)
        else:
            # übergeben iv
            mode_instance = self._get_cipher_instance(mode, package.iv)

        # decryption
        cipher = Cipher(algorithms.AES(self.key), mode_instance)
        decryptor = cipher.decryptor()

        try:
            plaintext = decryptor.update(package.ciphertext) + decryptor.finalize()
        except InvalidTag:
            raise ValueError("tag invalid")
        except Exception:
            raise ValueError("entschlüsselung fehlgeschlagen")

        # padding entfernen
        if mode in ["CBC", "ECB"]:
            plaintext = PaddingManager.unpad_data(plaintext)

        return plaintext