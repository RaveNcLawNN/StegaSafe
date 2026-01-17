import os
from dataclasses import dataclass
from typing import Optional
from cryptography.hazmat.primitives import padding
from stegasafe.utils.exceptions import CryptographyError

"""
cryptopackage ist ein container, der alle teile der verschlüsselten nachricht beinhaltet
wenn bspw. ein file mit AES-GCM verschlüsselt wird, haben wir als output den ciphertext, iv/nonce und ein tag
to_bytes serialisiert diese teile, from_bytes deserialisiert 
optional ermöglicht die felder "leer" zu behalten, da bspw. ECB kein iv und kein tag hat
"""

@dataclass
class CryptoPackage:
    ciphertext: bytes
    iv: Optional[bytes] = None
    tag: Optional[bytes] = None
    ephemeral_public_key: Optional[bytes] = None

    def to_bytes(self, mode: str) -> bytes:
        mode = mode.upper()
        output = b""

        if self.ephemeral_public_key:
            output += self.ephemeral_public_key

        if self.iv is not None:
            output += self.iv

        output += self.ciphertext

        if (mode == "GCM" or mode == "CHACHA20" or mode == "HYBRID") and self.tag is not None:
            output += self.tag

        return output

    @staticmethod
    def from_bytes(data: bytes, mode: str) -> 'CryptoPackage':
        mode = mode.upper()
        iv = None
        tag = None
        ephemeral_pub = None

        current_data = data

        if mode == "HYBRID":
            ephemeral_pub = current_data[:32]
            current_data = current_data[32:]
            mode = "GCM"

        if mode == "GCM":
            iv_len = 12
            tag_len = 16

            iv = current_data[:iv_len]
            tag = current_data[-tag_len:]
            ciphertext = current_data[iv_len:-tag_len]

        elif mode in ["CBC", "CTR", "CFB", "OFB"]:
            iv_len = 16
            iv = current_data[:iv_len]
            ciphertext = current_data[iv_len:]

        elif mode == "ECB":
            ciphertext = current_data

        return CryptoPackage(ciphertext=ciphertext, iv=iv, tag=tag, ephemeral_public_key=ephemeral_pub)

class IVGenerator:
    @staticmethod
    def generate(mode: str) -> bytes:
        if mode in ["GCM", "CHACHA20"]:
            return os.urandom(12)
        elif mode in ["CBC", "CTR", "CFB", "OFB"]:
            return os.urandom(16)
        elif mode in ["ECB"]:
            return b""
        else:
            raise CryptographyError(f"IV Generation failed: Unknown mode '{mode}'.")

"""
klasse für erstellung eines paddings für AES
für block-modes wie CBC und ECB brauchen wir padding, da wir mit festen blöcken (128 bits/16 bytes)arbeiten.
wenn die datei dann in blöcke aufgeteilt wird und nicht exakt in die blöcke passt, müssen diese gepadded werden.
"""

class PaddingManager:
    @staticmethod
    def pad_data(data: bytes, block_size: int = 128) -> bytes:
        padder = padding.PKCS7(block_size).padder()
        return padder.update(data) + padder.finalize()

    @staticmethod
    def unpad_data(data: bytes, block_size: int = 128) -> bytes:
        try:
            unpadder = padding.PKCS7(block_size).unpadder()
            return unpadder.update(data) + unpadder.finalize()
        except ValueError:
            raise CryptographyError("Decryption failed: Data padding is incorrect. This usually indicates an incorrect key.")