from PIL import Image, ExifTags
from stegasafe.utils.exceptions import SteganographyError

class MetadataStego:
    TAG_ID = 0x010E

    @staticmethod
    def embed(image_path, output_path, text):
        try:
            img = Image.open(image_path)

            # EXIF-Daten laden (oder leeres Objekt erstellen, falls keine da sind)
            exif = img.getexif()

            # Text in das Description-Feld schreiben
            # Hinweis: EXIF erwartet Strings oder Bytes.
            exif[MetadataStego.TAG_ID] = text

            # Speichern
            # WICHTIG: exif=exif muss übergeben werden.
            # Bei JPG/TIFF bleiben die Pixel erhalten (ggf. neu komprimiert bei JPG),
            # aber der Header wird aktualisiert.
            img.save(output_path, exif=exif)
            print(exif)

            return True, f"Saved to metadata header in {output_path}"
        except Exception as e:
            raise SteganographyError(f"Metadata Error: {str(e)}")

    @staticmethod
    def extract(image_path):
        try:
            img = Image.open(image_path)
            exif = img.getexif()

            if exif and MetadataStego.TAG_ID in exif:
                # Den Inhalt des Tags zurückgeben
                return str(exif[MetadataStego.TAG_ID])

            return None  # Nichts gefunden
        except Exception as e:
            raise SteganographyError(f"Metadata Extraction Error: {str(e)}")