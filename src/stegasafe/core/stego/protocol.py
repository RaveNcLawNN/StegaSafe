import struct
from stegasafe.utils.converter import DataConverter
from stegasafe.utils.compressor import Compressor
from stegasafe.utils.exceptions import ProcessingError

"""
protocol.py handles payload packing/unpacking
"""

HEADER_SIZE = 4 # default header size for storing the payload length

"""Prepares the raw payload for the embedding (Convert, Compress, Wrap)"""
def prepare_payload(text, input_format, use_compression, custom_delimiter=None):
    try:
        payload = DataConverter.to_bytes(text, input_format)

        if use_compression:
            payload = Compressor.compress(payload)

        payload_len = len(payload)

        if custom_delimiter:
            delimiter_bytes = custom_delimiter.encode('utf-8')
            full_message = payload + delimiter_bytes
            overhead = len(delimiter_bytes)
        else:
            header = struct.pack('>I', payload_len)
            full_message = header + payload
            overhead = HEADER_SIZE

        return full_message, payload_len, overhead
    except Exception:
        raise ProcessingError(f"Payload preparation failed.")

"""Converts, decompresses and formats raw bytes"""
def process_raw_data(raw_data, output_format, use_compression):
    if use_compression:
        try:
            raw_data = Compressor.decompress(raw_data)
        except Exception:
            raise ProcessingError(f"Decompression failed. Data corrupted or settings mismatch.")

    try:
        return DataConverter.from_bytes(raw_data, output_format)
    except Exception:
        raise ProcessingError(f"Data conversion failed.")