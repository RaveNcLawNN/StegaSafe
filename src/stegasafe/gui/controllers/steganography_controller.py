import shutil
import time
from pathlib import Path
from PyQt6.QtWidgets import QFileDialog, QMessageBox

from src.stegasafe.core.stego import lsb, capacity, metadata_cleaner, metadata_stego
from src.stegasafe.utils.converter import DataConverter
from src.stegasafe.utils.compressor import Compressor
from stegasafe.utils.decorators import handle_ui_errors

"""Controller for LSB & Metadata steganography"""

class SteganographyTabController:
    def __init__(self, ui):
        self.ui = ui
        self.current_max_bytes = 0
        self._init_ui_defaults()
        self._wire_events()

    """Sets the initial window state"""
    def _init_ui_defaults(self):
        if self.ui.cbInputFormat.count() == 0:
            self.ui.cbInputFormat.addItems(["UTF-8", "Base64", "Hex"])

        if hasattr(self.ui, 'cbExtractFormat') and self.ui.cbExtractFormat.count() == 0:
            self.ui.cbExtractFormat.addItems(["UTF-8", "Hex", "Base64"])

        if hasattr(self.ui, 'cbChannel') and self.ui.cbChannel.count() == 0:
            self.ui.cbChannel.addItems(["RGB (All Channels)", "Red Channel Only", "Green Channel Only", "Blue Channel Only"])

        if hasattr(self.ui, 'cbExtractChannel') and self.ui.cbExtractChannel.count() == 0:
            self.ui.cbExtractChannel.addItems(["RGB (All Channels)", "Red Channel Only", "Green Channel Only", "Blue Channel Only"])

        if hasattr(self.ui, 'cbEmbedMethod') and self.ui.cbEmbedMethod.count() == 0:
            self.ui.cbEmbedMethod.addItems(["LSB (Pixel Manipulation)", "Metadata (Header Injection)"])

        if hasattr(self.ui, 'cbExtractMethod') and self.ui.cbExtractMethod.count() == 0:
            self.ui.cbExtractMethod.addItems(["LSB (Pixel Manipulation)", "Metadata (Header Injection)"])

        self.ui.chkCleanMetadata.setChecked(True)
        self.ui.lblUsage.setText("Usage: - / -")

        self._toggle_ui_mode(is_extract=False)
        self._toggle_ui_mode(is_extract=True)

    """Connects actions to functions"""
    def _wire_events(self):
        self.ui.btnBrowseCover.clicked.connect(self._on_browse_cover)
        self.ui.btnEmbed.clicked.connect(self._embed_message)

        self.ui.pteEmbedMessage.textChanged.connect(self._update_usage_display)
        self.ui.cbInputFormat.currentTextChanged.connect(self._update_usage_display)
        self.ui.chkCompress.stateChanged.connect(self._update_usage_display)

        if hasattr(self.ui, 'leEmbedCustomDelimiter'):
            self.ui.leEmbedCustomDelimiter.textChanged.connect(self._update_usage_display)

        if hasattr(self.ui, 'leEmbedSeed'):
            self.ui.leEmbedSeed.textChanged.connect(self._update_usage_display)

        if hasattr(self.ui, 'cbChannel'):
            self.ui.cbChannel.currentIndexChanged.connect(self._update_usage_display)

        if hasattr(self.ui, 'cbEmbedMethod'):
            self.ui.cbEmbedMethod.currentIndexChanged.connect(lambda: self._toggle_ui_mode(is_extract=False))
            self.ui.cbEmbedMethod.currentIndexChanged.connect(self._update_usage_display)

        if hasattr(self.ui, 'cbExtractMethod'):
            self.ui.cbExtractMethod.currentIndexChanged.connect(lambda: self._toggle_ui_mode(is_extract=True))

        self.ui.btnBrowseStego.clicked.connect(lambda: self._choose_file(self.ui.leStegoPath))
        self.ui.btnExtract.clicked.connect(self._extract_message)

    """Activates/Deactivates UI elements based on the method used"""
    def _toggle_ui_mode(self, is_extract):
        if is_extract:
            combo = getattr(self.ui, 'cbExtractMethod', None)
            is_metadata = combo and "Metadata" in combo.currentText()

            elements_to_toggle = [
                getattr(self.ui, 'cbExtractChannel', None),
                getattr(self.ui, 'leExtractSeed', None),
                getattr(self.ui, 'leExtractCustomDelimiter', None),
                getattr(self.ui, 'cbExtractFormat', None),
                getattr(self.ui, 'chkExtractCompress', None)
            ]
        else:
            combo = getattr(self.ui, 'cbEmbedMethod', None)
            is_metadata = combo and "Metadata" in combo.currentText()

            elements_to_toggle = [
                getattr(self.ui, 'cbChannel', None),
                getattr(self.ui, 'leEmbedSeed', None),
                getattr(self.ui, 'leEmbedCustomDelimiter', None),
                getattr(self.ui, 'chkCleanMetadata', None),
                getattr(self.ui, 'cbInputFormat', None),
                getattr(self.ui, 'chkCompress', None)
            ]

        for el in elements_to_toggle:
            if el:
                el.setEnabled(not is_metadata)

        if not is_extract and is_metadata and hasattr(self.ui, 'chkCleanMetadata'):
            self.ui.chkCleanMetadata.setChecked(False)

    """Opens file explorer to choose carrying image - for now .png, .jpg, .jpeg and .tiff"""
    def _choose_file(self, line_edit):
        path, _ = QFileDialog.getOpenFileName(
            self.ui, "Select Image", "", "Images (*.png *.jpg *.jpeg *.tiff *.bmp);;All Files (*)"
        )
        if path:
            line_edit.setText(path)
            return path
        return None

    """Automatically converts bytes into KB or MB"""
    def _format_size(self, size_in_bytes):
        if size_in_bytes < 1024:
            return f"{size_in_bytes} B"
        elif size_in_bytes < 1024 * 1024:
            return f"{size_in_bytes / 1024:.2f} KB"
        else:
            return f"{size_in_bytes / (1024 * 1024):.2f} MB"

    """Helper to get the channel mode setting"""
    def _get_channel_mode(self, is_extract=False):
        combo = None
        if is_extract:
            combo = getattr(self.ui, 'cbExtractChannel', None)
        else:
            combo = getattr(self.ui, 'cbChannel', None)

        if not combo:
            return "all"

        txt = combo.currentText().lower()
        if "red" in txt: return "red"
        if "green" in txt: return "green"
        if "blue" in txt: return "blue"
        return "all"

    """Helper for Embed Method check"""
    def _is_metadata_mode(self, is_extract=False):
        combo = getattr(self.ui, 'cbExtractMethod' if is_extract else 'cbEmbedMethod', None)
        return combo and "Metadata" in combo.currentText()

    """Calls choose file and calculates maximum capacity automatically"""
    @handle_ui_errors
    def _on_browse_cover(self, *args):
        path = self._choose_file(self.ui.leCoverPath)
        if path:
            mode = self._get_channel_mode(is_extract=False)
            self.current_max_bytes = capacity.get_max_bytes_pure(path)
            self._update_usage_display()

    """Reads custom delimiter from leExtractCustomDelimiter / leEmbedCustomDelimiter"""
    def _get_delimiter(self, is_extract=False):
        if is_extract:
            field = getattr(self.ui, 'leExtractCustomDelimiter', None)
        else:
            field = getattr(self.ui, 'leEmbedCustomDelimiter', None)

        if field:
            val = field.text()
            if val:
                return val
            return None
        return None

    """Reads custom seed / password from leExtractSeed / leEmbedSeed"""
    def _get_seed(self, is_extract=False):
        if is_extract:
            field = getattr(self.ui, 'leExtractSeed', None)
        else:
            field = getattr(self.ui, 'leEmbedSeed', None)

        if field:
            val = field.text()
            if val and val.strip():
                if val.isdigit():
                    return int(val)
                else:
                    return hash(val)
        return None

    """Runs everytime the payload changes. Checks whether image is loaded, simulates compression, adds overhead, calculates current size / max capacity and updates visuals"""
    def _update_usage_display(self):
        if self._is_metadata_mode(is_extract=False):
            self.ui.lblUsage.setText("Mode: Metadata Header (No Size Limit displayed")
            return

        if self.current_max_bytes == 0:
            self.ui.lblUsage.setText("Please select an image first.")
            return

        cover_path = self.ui.leCoverPath.text()
        if cover_path:
            mode = self._get_channel_mode(is_extract=False)
            try:
                self.current_max_bytes = capacity.get_max_bytes_pure(cover_path, mode)
            except: pass

        text = self.ui.pteEmbedMessage.toPlainText()
        input_format = self.ui.cbInputFormat.currentText().lower()
        use_compression = self.ui.chkCompress.isChecked()
        delimiter = self._get_delimiter(is_extract=False)

        try:
            if not text:
                current_bytes = 0
            else:
                payload = DataConverter.to_bytes(text, input_format)
                if use_compression:
                    payload = Compressor.compress(payload)

                if delimiter:
                    overhead = len(delimiter.encode('utf-8'))
                else:
                    overhead = 4

                current_bytes = len(payload) + overhead

            curr_str = self._format_size(current_bytes)
            max_str = self._format_size(self.current_max_bytes)
            percent = (current_bytes / self.current_max_bytes) * 100

            self.ui.lblUsage.setText(f"Usage: {curr_str} / {max_str} ({percent:.1f}%)")

            if current_bytes > self.current_max_bytes:
                self.ui.lblUsage.setStyleSheet("color: red; font-weight: bold;")
            elif percent > 90:
                self.ui.lblUsage.setStyleSheet("color: orange; font-weight: bold;")
            else:
                self.ui.lblUsage.setStyleSheet("color: green;")

        except Exception:
            self.ui.lblUsage.setText("Invalid Input Format")
            self.ui.lblUsage.setStyleSheet("color: red;")

    """Runs upon embedding the payload"""
    @handle_ui_errors
    def _embed_message(self, *args):
        cover_path = self._require_file(self.ui.leCoverPath.text())
        message = self.ui.pteEmbedMessage.toPlainText()
        if not message:
            raise ValueError("Message cannot be empty.")

        if self._is_metadata_mode(is_extract=False):
            p = Path(cover_path)
            default_out = str(p.with_stem(p.stem + "_meta"))
            output_path, _ = QFileDialog.getSaveFileName(self.ui, "Save Stego (Metadata) Image", default_out, "JPEG Image (*.jpg *.jpeg);;TIFF Image (*.tiff *.tif)")

            if not output_path: return

            success, msg = metadata_stego.MetadataStego.embed(cover_path, output_path, message)
            self.ui.pteEmbedMessage.clear()
            QMessageBox.information(self.ui, "Success", msg)

        else:
            input_format = self.ui.cbInputFormat.currentText().lower()
            use_compression = self.ui.chkCompress.isChecked()
            should_clean_metadata = self.ui.chkCleanMetadata.isChecked()
            delimiter = self._get_delimiter(is_extract=False)
            seed = self._get_seed(is_extract=False)
            channel_mode = self._get_channel_mode(is_extract=False)

            # Raises CapacityError if data is too big
            capacity.validate_capacity(cover_path, message, input_format, use_compression, custom_delimiter=delimiter, channel_mode=channel_mode)

            p = Path(cover_path)
            default_out = str(p.with_stem(p.stem + "_payload").with_suffix(".png"))
            output_path, _ = QFileDialog.getSaveFileName(self.ui, "Save Stego (LSB) Image", default_out, "PNG Image (*.png)")

            if not output_path:
                return

            if not output_path.lower().endswith(".png"):
                output_path = output_path + ".png"

            if should_clean_metadata:
                metadata_cleaner.clean_metadata(cover_path, output_path)
            else:
                shutil.copy2(cover_path, output_path)

            lsb.encode_text(
                image_path=output_path,
                output_path=output_path,
                text=message,
                input_format=input_format,
                use_compression=use_compression,
                custom_delimiter=delimiter,
                seed=seed,
                channel_mode=channel_mode
            )

            self.ui.pteEmbedMessage.clear()
            QMessageBox.information(self.ui, "Success", f"Message hidden in:\n{output_path}")
            self._update_usage_display()

    """Runs upon extracting the payload"""

    @handle_ui_errors
    def _extract_message(self, *args):
        stego_path = self._require_file(self.ui.leStegoPath.text())

        if hasattr(self.ui, 'chkDebugDump') and self.ui.chkDebugDump.isChecked():
            self._perform_debug_dump(stego_path)
            return

        if self._is_metadata_mode(is_extract=True):
            result = metadata_stego.MetadataStego.extract(stego_path)
            self.ui.tbExtractedMessage.setText(result)
            if hasattr(self.ui, 'chkAutoSave') and self.ui.chkAutoSave.isChecked():
                self._save_text_with_dialog(result, stego_path)

        else:
            extract_format = self.ui.cbExtractFormat.currentText().lower() if hasattr(self.ui, 'cbExtractFormat') else "utf-8"
            extract_compression = self.ui.chkExtractCompress.isChecked() if hasattr(self.ui, 'chkExtractCompress') else False
            delimiter = self._get_delimiter(is_extract=True)
            seed = self._get_seed(is_extract=True)
            channel_mode = self._get_channel_mode(is_extract=True)

            # lsb.decode_text raises SteganographyError if extraction fails
            result = lsb.decode_text(
                image_path=stego_path,
                output_format=extract_format,
                use_compression=extract_compression,
                custom_delimiter=delimiter,
                seed=seed,
                channel_mode=channel_mode
            )

            self.ui.tbExtractedMessage.setText(result)
            if hasattr(self.ui, 'chkAutoSave') and self.ui.chkAutoSave.isChecked():
                self._save_text_with_dialog(result, stego_path)

    """Calls lsb.debug_dump_raw"""
    @handle_ui_errors
    def _perform_debug_dump(self, image_path):
        raw_bytes = lsb.debug_dump_raw(image_path)
        formatted_dump = self._format_hexdump(raw_bytes)

        display_text = formatted_dump[:20000]
        if len(formatted_dump) > 20000:
            display_text = display_text + "\n\n Maximum display size (20.000 characters) reached. Enable Autosave to get full dump"

        self.ui.tbExtractedMessage.setText(display_text)

        if hasattr(self.ui, 'chkAutoSave'):
            if self.ui.chkAutoSave.isChecked():
                self._save_text_with_dialog(formatted_dump, image_path)
        else:
            QMessageBox.information(self.ui, "Debug Dump", "Raw bits extracted to text field.\n(Enable Autosave to save the full dump to a file)")

    """Formats the debug dump into a classic hex-editor view (Offset | Hex | ASCII)"""
    def _format_hexdump(self, data):
        lines = []
        chunk_size = 16
        lines.append(f"{'OFFSET':<8}  {'HEX BYTES':<48}  {'ASCII'}")
        lines.append("-" * 76)
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:08X}  {hex_part:<48}  {ascii_part}")
        return "\n".join(lines)

    """Saves the output into a .txt when Autosave is enabled"""
    def _save_text_with_dialog(self, text_data, source_image_path):
        try:
            p = Path(source_image_path)
            default_filename = f"{p.stem}_extracted.txt"
            suggested_path = str(p.parent / default_filename)
            file_path, _ = QFileDialog.getSaveFileName(
                self.ui, "Save Extracted Data", suggested_path, "Text Files (*.txt);;All Files (*)"
            )
            if file_path:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(text_data)
        except Exception as e:
            self._show_error("Save Error", str(e))

    """A helper that checks whether a file path is valid."""
    def _require_file(self, path_str: str) -> str:
        if not path_str:
            raise ValueError("No file selected.")
        p = Path(path_str)
        if not p.exists() or not p.is_file():
            raise ValueError("Selected file does not exist.")
        return str(p)