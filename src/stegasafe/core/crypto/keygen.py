import os

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
