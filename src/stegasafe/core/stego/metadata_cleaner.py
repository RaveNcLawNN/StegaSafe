from PIL import Image

def clean_metadata(image_path, output_path):
    try:
        image = Image.open(image_path)
        data = list(image.getdata())
        image_without_exif = Image.new(image.mode, image.size)
        image_without_exif.putdata(data)
        image_without_exif.save(output_path, "PNG")
        return True
    except Exception:
        return False