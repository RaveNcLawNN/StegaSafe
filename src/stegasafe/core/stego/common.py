from PIL import Image
import numpy as np
from stegasafe.utils.exceptions import SteganographyError

"""
common.py contains helper functions
"""

"""Converts an image into an array and flattens it so we have a chain of [R, G, B] pixels"""
def load_image_data(image_path):
    try:
        img = Image.open(image_path).convert('RGB')
        pixels = np.array(img)
        return img, pixels, pixels.flatten()
    except Exception as e:
        # Wrap PIL or OS errors into a human-readable SteganographyError
        raise SteganographyError(f"Failed to load image data: {str(e)}")

"""Converts the NumPy array into an RGB image.png and saves it"""
def save_image_from_pixels(pixels_array, original_shape, output_path):
    try:
        encoded_pixels = pixels_array.reshape(original_shape)
        encoded_img = Image.fromarray(encoded_pixels.astype('uint8'), 'RGB')
        encoded_img.save(output_path, "PNG")
    except Exception as e:
        # Provide clear feedback if the carrier image cannot be saved
        raise SteganographyError(f"Failed to save processed image to disk: {str(e)}")

"""Calculates the maximum capacity of bytes that can be used to hide something - channel_count: 3 for full RGB, 1 for single channel"""
def get_max_bytes_pure(image_path, channel_count=3):
    try:
        with Image.open(image_path) as image:
            width, height = image.size

            if channel_count == 1:
                maximum_bits = width * height * 1
            else:
                maximum_bits = width * height * 3

            maximum_bytes = maximum_bits // 8
            return maximum_bytes
    except Exception as e:
        # Ensures capacity checks provide descriptive errors rather than crashing
        raise SteganographyError(f"Failed to calculate image capacity: {str(e)}")