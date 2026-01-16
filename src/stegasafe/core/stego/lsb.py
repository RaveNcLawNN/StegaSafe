import numpy as np
import random
from stegasafe.utils.converter import DataConverter
from . import common
from . import protocol
from stegasafe.utils.exceptions import SteganographyError, CapacityError

"""Creates a list of indices based on the selected channel mode that determine which pixels are overwritten"""
def _get_pixel_indices(total_pixels, required_bits, seed=None, channel_mode="all"):
    if channel_mode == "red":
        indices = list(range(0, total_pixels, 3))
    elif channel_mode == "green":
        indices = list(range(1, total_pixels, 3))
    elif channel_mode == "blue":
        indices = list(range(2, total_pixels, 3))
    else:
        indices = list(range(total_pixels))

    if seed is not None:
        random.seed(seed)
        random.shuffle(indices)

    if required_bits is not None:
        if required_bits > len(indices):
            raise CapacityError(f"Not enough pixels available in the selected channel mode ({channel_mode}).")
        return indices[:required_bits]

    return indices

"""Embeds the payload within the selected image and channel"""
def encode_text(image_path, output_path, text, input_format="utf-8", use_compression=False, custom_delimiter=None, seed=None, channel_mode="all"):
    try:
        preparation_result = protocol.prepare_payload(text, input_format, use_compression, custom_delimiter)
        full_message_bytes = preparation_result[0]
        payload_len = preparation_result[1]

        binary_message_string = DataConverter.bytes_to_bits(full_message_bytes)
        number_of_bits = len(binary_message_string)

        original_shape, flat_pixels = common.load_image_data(image_path)

        target_indices = _get_pixel_indices(flat_pixels.size, number_of_bits, seed, channel_mode)

        for i in range(number_of_bits):
            current_bit = int(binary_message_string[i])
            pixel_index = target_indices[i]
            flat_pixels[pixel_index] = (flat_pixels[pixel_index] & 254) | current_bit

        common.save_image_from_pixels(flat_pixels, original_shape, output_path)

        if seed:
            mode_info = f"Non-Sequential LSB (Seed: {seed})"
        else:
            mode_info = "Sequential LSB"

        print(f"Saved image to {output_path}. Mode: {mode_info}. Payload: {payload_len} bytes.")
    except (CapacityError, SteganographyError):
        raise
    except Exception as e:
        raise SteganographyError(f"Embedding failed: {str(e)}")


# """Extracts the payload out of the selected image"""
# def decode_text(image_path, output_format="utf-8", use_compression=False, custom_delimiter=None, seed=None, channel_mode="all"):
#     try:
#         _, _, flat_pixels = common.load_image_data(image_path)
#
#         indices = _get_pixel_indices(flat_pixels.size, None, seed, channel_mode)
#
#         extracted_bits_string = ""
#         raw_data = b""
#
#         if custom_delimiter:
#             delimiter_bytes = custom_delimiter.encode('utf-8')
#             collected_bits = ""
#             for i in range(len(indices)):
#                 pixel_idx = indices[i]
#                 pixel_value = flat_pixels[pixel_idx]
#                 lsb = pixel_value & 1
#
#                 collected_bits = collected_bits + str(lsb)
#
#                 if len(collected_bits) % 8 == 0:
#                     try:
#                         current_bytes = DataConverter.bits_to_bytes(collected_bits)
#                         found_index = current_bytes.find(delimiter_bytes)
#
#                         if found_index != -1:
#                             raw_data = current_bytes[:found_index]
#                             break
#                     except:
#                         pass
#
#             if raw_data == b"":
#                 # Error for delimiter mismatch
#                 raise SteganographyError(
#                     "Custom delimiter could not be located. Ensure you are using the correct delimiter and seed.")
#
#         else:
#             header_bits = ""
#             if len(indices) < 32:
#                 raise SteganographyError("The image is too small to contain a valid StegaSafe header.")
#
#             for i in range(32):
#                 pixel_idx = indices[i]
#                 pixel_value = flat_pixels[pixel_idx]
#                 lsb = pixel_value & 1
#                 header_bits = header_bits + str(lsb)
#
#             payload_length = int(header_bits, 2)
#
#             max_possible_bytes = (flat_pixels.size - 32) // 8
#             if payload_length < 0 or payload_length > max_possible_bytes:
#                 # Specific error for header corruption or wrong seed
#                 raise SteganographyError("A valid hidden message header could not be located. "
#                                          "Ensure you are using the correct seed or channel mode.")
#
#             payload_bits_needed = payload_length * 8
#             payload_bits_string = ""
#
#             for i in range(payload_bits_needed):
#                 list_index = 32 + i
#                 pixel_idx = indices[list_index]
#
#                 pixel_value = flat_pixels[pixel_idx]
#                 lsb = pixel_value & 1
#                 payload_bits_string = payload_bits_string + str(lsb)
#
#             raw_data = DataConverter.bits_to_bytes(payload_bits_string)
#
        return protocol.process_raw_data(raw_data, output_format, use_compression)

    except SteganographyError:
        # Re-raise known stego errors
        raise
    except Exception as e:
        # Wrap technical processing errors
        raise SteganographyError(f"Extraction failed: {str(e)}")



"""Extracts the payload out of the selected image"""
def decode_text(image_path, output_format="utf-8", use_compression=False, custom_delimiter=None, seed=None, channel_mode="all"):
    try:
        _, flat_pixels = common.load_image_data(image_path)
        indices = _get_pixel_indices(flat_pixels.size, None, seed, channel_mode)

        raw_data = b""

        if custom_delimiter:
            delimiter_bytes = custom_delimiter.encode('utf-8')
            bit_buffer = []
            byte_list = bytearray()

            for i in range(len(indices)):
                pixel_idx = indices[i]
                bit_buffer.append(str(flat_pixels[pixel_idx] & 1))

                if len(bit_buffer) == 8:
                    byte_val = int("".join(bit_buffer), 2)
                    byte_list.append(byte_val)
                    bit_buffer = []

                    if byte_list.endswith(delimiter_bytes):
                        raw_data = bytes(byte_list[:-len(delimiter_bytes)])
                        break

            if not raw_data and not byte_list.endswith(delimiter_bytes):
                raise SteganographyError("Custom delimiter could not be located.")

        else:
            if len(indices) < 32:
                raise SteganographyError("Image too small for header.")

            header_bits = "".join(str(flat_pixels[indices[i]] & 1) for i in range(32))
            payload_length = int(header_bits, 2)

            max_possible_bytes = (len(indices) - 32) // 8
            if payload_length < 0 or payload_length > max_possible_bytes:
                raise SteganographyError("Invalid header found. Wrong seed or channel mode?")

            bits = []
            for i in range(payload_length * 8):
                idx = indices[32 + i]
                bits.append(str(flat_pixels[idx] & 1))

            binary_str = "".join(bits)
            raw_data = DataConverter.bits_to_bytes(binary_str)

        return protocol.process_raw_data(raw_data, output_format, use_compression)

    except Exception as e:
        if isinstance(e, SteganographyError):
            raise
        raise SteganographyError(f"Extraction failed: {str(e)}")

"""Reads and dumps LSB content of the entire image file"""
def debug_dump_raw(image_path, limit_bytes=None):
    _, flat_pixels = common.load_image_data(image_path)

    if limit_bytes:
        limit_bits = limit_bytes * 8
    else:
        limit_bits = len(flat_pixels)

    relevant_pixels = flat_pixels[:limit_bits]

    extracted_bits = relevant_pixels & 1

    return np.packbits(extracted_bits).tobytes()