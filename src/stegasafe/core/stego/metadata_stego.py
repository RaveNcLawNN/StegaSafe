from PIL import Image, ExifTags
from stegasafe.utils.exceptions import SteganographyError

class MetadataStego:
    TAG_ID = 0x010E

    @staticmethod
    def embed(image_path, output_path, text):
        try:
            img = Image.open(image_path)
            exif = img.getexif()
            exif[MetadataStego.TAG_ID] = text
            img.save(output_path, exif=exif)
            print(exif)

            return True, f"Saved to metadata header in {output_path}"
        except Exception:
            raise SteganographyError(f"Metadata Error.")

    @staticmethod
    def extract(image_path):
        try:
            img = Image.open(image_path)
            exif = img.getexif()

            if exif and MetadataStego.TAG_ID in exif:
                return str(exif[MetadataStego.TAG_ID])

            return None
        except Exception:
            raise SteganographyError(f"Metadata Extraction Error.")