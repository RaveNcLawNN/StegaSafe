from PIL import Image
import numpy as np

"""
common.py contains helper functions
"""

"""Converts an image into an array and flattens it so we have a chain of [R, G, B] pixels"""
def load_image_data(image_path):
    img = Image.open(image_path).convert('RGB')
    pixels = np.array(img)
    return img, pixels, pixels.flatten()

"""Converts the NumPy array into an RGB image.png and saves it"""
def save_image_from_pixels(pixels_array, original_shape, output_path):
    encoded_pixels = pixels_array.reshape(original_shape)
    encoded_img = Image.fromarray(encoded_pixels.astype('uint8'), 'RGB')
    encoded_img.save(output_path, "PNG")

"""Calculates the maximum capacity of bytes that can be used to hide something"""
def get_max_bytes_pure(image_path):
    with Image.open(image_path) as image:
        width, height = image.size
        maximum_bits = width * height * 3
        maximum_bytes = maximum_bits // 8
        return maximum_bytes