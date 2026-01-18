import base64
import binascii

"""
converter.py handles data conversion for steganography
"""

class DataConverter:

    @staticmethod
    def to_bytes(data: str, format: str) -> bytes:
        try:
            if format == "utf-8":
                return data.encode('utf-8')

            elif format == "hex":
                clean_data = data.replace(" ", "")
                clean_data = clean_data.replace("0x", "")
                return bytes.fromhex(clean_data)

            elif format == "base64":
                return base64.b64decode(data)

            else:
                raise ValueError("Format not supported, use UTF-8, Hex or Base64")

        except (binascii.Error, ValueError) as e:
            raise ValueError("error converting data")

    @staticmethod
    def from_bytes(data: bytes, format: str) -> str:
        if format == "utf-8":
            return data.decode('utf-8')

        elif format == "hex":
            return data.hex()

        elif format == "base64":
            encoded_bytes = base64.b64encode(data)
            result_string = encoded_bytes.decode("utf-8")
            return result_string

        else:
            raise ValueError("Format not supported, use UTF-8, Hex or Base64")

    @staticmethod
    def bytes_to_bits(data: bytes) -> str:
        result_bits = ""

        for single_byte in data:
            binary_string = format(single_byte, '08b')
            result_bits = result_bits + binary_string
        return result_bits

    @staticmethod
    def bits_to_bytes(bits: str) -> bytes:
        if len(bits) % 8 != 0:
            raise ValueError("bits length must be multiple of 8")

        byte_array = bytearray()

        for i in range(0, len(bits), 8):
            byte_chunk = bits[i : i + 8]
            byte_value = int(byte_chunk, 2)
            byte_array.append(byte_value)
        return bytes(byte_array)
