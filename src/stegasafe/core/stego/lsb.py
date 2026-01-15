import numpy as np
import random
from stegasafe.utils.converter import DataConverter
from . import common
from . import protocol

"""Creates a list of indices that determine which pixels are overwritten - default without seed [0, 1, 2, 3, ...]"""
def _get_pixel_indices(total_pixels, required_bits, seed=None):
    indices = list(range(total_pixels))

    if seed is not None:
        random.seed(seed)
        random.shuffle(indices)

    if required_bits is not None:
        selected_indices = []
        for i in range(required_bits):
            selected_indices.append(indices[i])
        return selected_indices
    return indices

"""Embeds the payload within the selected image"""
def encode_text(image_path, output_path, text, input_format="utf-8", use_compression=False, custom_delimiter=None, seed=None):
    preparation_result = protocol.prepare_payload(text, input_format, use_compression, custom_delimiter)
    full_message_bytes = preparation_result[0]
    payload_len = preparation_result[1]

    binary_message_string = DataConverter.bytes_to_bits(full_message_bytes)
    number_of_bits = len(binary_message_string)
    img, pixels, flat_pixels = common.load_image_data(image_path)

    if number_of_bits > flat_pixels.size:
        raise ValueError("The provided payload is too large for the selected image. Try compressing the payload, or select a different image")

    target_indices = _get_pixel_indices(flat_pixels.size, number_of_bits, seed)

    for i in range(number_of_bits):
        current_bit = int(binary_message_string[i])
        pixel_index = target_indices[i]
        current_pixel_value = flat_pixels[pixel_index]
        pixel_without_lsb = current_pixel_value & 254
        new_pixel_value = pixel_without_lsb | current_bit
        flat_pixels[pixel_index] = new_pixel_value

    common.save_image_from_pixels(flat_pixels, pixels.shape, output_path)

    if seed:
        mode_info = f"Non-Sequential LSB (Seed: {seed})"
    else:
        mode_info = "Sequential LSB"

    print(f"Saved image to {output_path}. Mode: {mode_info}. Payload: {payload_len} bytes.")

"""Extracts the payload out of the selected image"""
def decode_text(image_path, output_format="utf-8", use_compression=False, custom_delimiter=None, seed=None):
    _, _, flat_pixels = common.load_image_data(image_path)

    indices = _get_pixel_indices(flat_pixels.size, None, seed)

    extracted_bits_string = ""
    raw_data = b""

    if custom_delimiter:
        delimiter_bytes = custom_delimiter.encode('utf-8')
        collected_bits = ""
        for i in range(len(indices)):
            pixel_idx = indices[i]
            pixel_value = flat_pixels[pixel_idx]
            lsb = pixel_value & 1

            collected_bits = collected_bits + str(lsb)

            if len(collected_bits) % 8 == 0:
                try:
                    current_bytes = DataConverter.bits_to_bytes(collected_bits)

                    found_index = current_bytes.find(delimiter_bytes)

                    if found_index != -1:
                        raw_data = current_bytes[:found_index]
                        break
                except:
                    pass

        if raw_data == b"":
            return "Custom delimiter could not be located. Make sure you are using the correct delimiter / seed."

    else:
        header_bits = ""
        for i in range(32):
            pixel_idx = indices[i]
            pixel_value = flat_pixels[pixel_idx]
            lsb = pixel_value & 1
            header_bits = header_bits + str(lsb)

        payload_length = int(header_bits, 2)

        max_possible_bytes = (flat_pixels.size - 32) // 8
        if payload_length < 0 or payload_length > max_possible_bytes:
            return "A valid header could not be located. Make sure you are using the correct seed."

        payload_bits_needed = payload_length * 8
        payload_bits_string = ""

        for i in range(payload_bits_needed):
            list_index = 32 + i
            pixel_idx = indices[list_index]

            pixel_value = flat_pixels[pixel_idx]
            lsb = pixel_value & 1
            payload_bits_string = payload_bits_string + str(lsb)

        raw_data = DataConverter.bits_to_bytes(payload_bits_string)

    try:
        return protocol.process_raw_data(raw_data, output_format, use_compression)
    except Exception as e:
        return str(e)

"""Reads and dumps content of the entire image file"""
def debug_dump_raw(image_path, limit_bytes=None):
    _, _, flat_pixels = common.load_image_data(image_path)

    bits_string = ""

    if limit_bytes:
        limit_bits = limit_bytes * 8
    else:
        limit_bits = len(flat_pixels)

    for i in range(limit_bits):
        val = flat_pixels[i]
        lsb = val & 1
        bits_string = bits_string + str(lsb)

    return np.packbits(np.array(list(bits_string), dtype=int)).tobytes()