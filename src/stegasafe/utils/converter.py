import base64
import binascii

class DataConverter:
    @staticmethod
    def to_bytes(data: str, format: str) -> bytes:

        try:
            if format == "utf-8":
                return data.encode('utf-8')

            elif format == "hex":
                clean_data = data.replace(" ", "").replace("0x", "")
                return bytes.fromhex(clean_data)

            elif format == "base64":
                return base64.b64decode(data)

            else:
                raise ValueError("unknown format, use utf8, hex, base64")

        except (binascii.Error, ValueError) as e:
            raise ValueError("error converting data")

    @staticmethod
    def from_bytes(data: bytes, format: str) -> str:

        if format == "utf-8":
            return data.decode('utf-8')

        elif format == "hex":
            return data.hex()

        elif format == "base64":
            return base64.b64encode(data).decode("utf-8")

        else:
            raise ValueError("unknown format, use utf8, hex, base64")

