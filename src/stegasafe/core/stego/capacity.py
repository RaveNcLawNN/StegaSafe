from . import common, protocol

def get_max_bytes(image_path):
    total_space = common.get_max_bytes_pure(image_path)
    header_size = protocol.HEADER_SIZE
    available_space = total_space - header_size
    return available_space

def get_max_bytes_pure(image_path):
    total_space = common.get_max_bytes_pure(image_path)
    return total_space

def validate_capacity(image_path, text_data, input_format="utf-8", use_compression=False, custom_delimiter=None):
    try:
        preparation_result = protocol.prepare_payload(image_path, input_format, use_compression, custom_delimiter)
        payload_len = preparation_result[1]
        overhead = preparation_result[2]

        required_bytes = payload_len + overhead
        total_available_bytes = common.get_max_bytes_pure(image_path)

        if required_bytes > total_available_bytes:
            raise ValueError("Data is too big")

        return True, "Capacity OK"
    except Exception as e:
        raise e