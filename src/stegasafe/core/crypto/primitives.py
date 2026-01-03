import os
from dataclasses import dataclass
from typing import Optional
from cryptography.hazmat.primitives import padding

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

    def to_bytes(self, mode: str) -> bytes:
        mode = mode.upper()
        output = b""

        if self.iv is not None:
            output += self.iv

        output += self.ciphertext

        if mode == "GCM" and self.tag is not None:
            output += self.tag

        return output

    @staticmethod
    def from_bytes(data: bytes, mode: str) -> 'CryptoPackage':
        mode = mode.upper()
        iv = None
        tag = None
        ciphertext = data

        if mode == "GCM":
            iv_len = 12
            tag_len = 16

            iv = data[:iv_len]
            tag = data[-tag_len:]
            ciphertext = data[iv_len:-tag_len]

        elif mode in ["CBC", "CTR", "CFB", "OFB"]:
            iv_len = 16

            iv = data[:iv_len]
            ciphertext = data[iv_len:]

        elif mode == "ECB":
            ciphertext = data

        return CryptoPackage(ciphertext=ciphertext, iv=iv, tag=tag)

class IVGenerator:
    @staticmethod
    def generate(mode: str) -> bytes:
        if mode == "GCM":
            return os.urandom(12)
        elif mode in ["CBC", "CTR", "CFB", "OFB"]:
            return os.urandom(16)
        elif mode in ["ECB"]:
            return b""
        else:
            raise ValueError("unbekannter mode")

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
            raise ValueError("padding fehler")
