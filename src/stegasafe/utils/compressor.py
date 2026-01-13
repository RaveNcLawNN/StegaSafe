import zlib

"""
compressor.py handles compression and decompression of data using zlib
"""

class Compressor:

    @staticmethod
    def compress(data: bytes) -> bytes:
        try:
            return zlib.compress(data, level=9) # max compression
        except Exception as e:
            raise ValueError("error")

    @staticmethod
    def decompress(data: bytes) -> bytes:
        try:
            return zlib.decompress(data)
        except Exception as e:
            raise ValueError("error")