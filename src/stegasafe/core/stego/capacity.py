from PIL import Image
from stegasafe.utils.exceptions import SteganographyError, CapacityError
from . import protocol

def get_max_bytes_pure(image_path, channel_mode="all"):
    channel_count = 1 if channel_mode in ["red", "green", "blue"] else 3

    with Image.open(image_path) as image:
        width, height = image.size
        total_space = (width * height * channel_count) // 8
        return total_space

def get_max_bytes(image_path, channel_mode="all"):
    total_space = get_max_bytes_pure(image_path, channel_mode)
    embed_space = total_space - protocol.HEADER_SIZE
    return embed_space

def validate_capacity(image_path, text_data, input_format="utf-8", use_compression=False, custom_delimiter=None, channel_mode="all"):
    try:
        full_data, _, _ = protocol.prepare_payload(image_path, input_format, use_compression, custom_delimiter)
        required_bytes = len(full_data)

        available_bytes = get_max_bytes_pure(image_path, channel_mode)

        if required_bytes > available_bytes:
            raise CapacityError(f"The message is too large for the selected carrier. "
                                f"Required: {required_bytes} bytes, Available: {available_bytes} bytes.")
        return True, "Capacity OK"
    except CapacityError:
        raise
    except Exception as e:
        raise SteganographyError(f"Capacity validation failed: {str(e)}")