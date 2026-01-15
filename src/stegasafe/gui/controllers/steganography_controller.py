import shutil
import time
from pathlib import Path
from PyQt6.QtWidgets import QFileDialog, QMessageBox

from src.stegasafe.core.stego import lsb, capacity, metadata_cleaner
from src.stegasafe.utils.converter import DataConverter
from src.stegasafe.utils.compressor import Compressor

"""Main controller for LSB steganography"""

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

        self.ui.chkCleanMetadata.setChecked(True)
        self.ui.lblUsage.setText("Usage: - / -")

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

        self.ui.btnBrowseStego.clicked.connect(lambda: self._choose_file(self.ui.leStegoPath))
        self.ui.btnExtract.clicked.connect(self._extract_message)

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

    """Calls choose file and calculates maximum capacity automatically"""
    def _on_browse_cover(self):
        path = self._choose_file(self.ui.leCoverPath)
        if path:
            try:
                self.current_max_bytes = capacity.get_max_bytes_pure(path)
                self._update_usage_display()
            except Exception:
                self.current_max_bytes = 0
                self.ui.lblUsage.setText("Error reading image")

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
        if self.current_max_bytes == 0:
            self.ui.lblUsage.setText("Please select an image first.")
            return

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

    """Runs upon embedding the payload - validates path, reads settings, checks capacity, calls lsb.encode_text"""
    def _embed_message(self):
        try:
            cover_path = self._require_file(self.ui.leCoverPath.text())
            message = self.ui.pteEmbedMessage.toPlainText()
            if not message:
                raise ValueError("Message cannot be empty.")

            input_format = self.ui.cbInputFormat.currentText().lower()
            use_compression = self.ui.chkCompress.isChecked()
            should_clean_metadata = self.ui.chkCleanMetadata.isChecked()

            delimiter = self._get_delimiter(is_extract=False)
            seed = self._get_seed(is_extract=False)

            capacity.validate_capacity(
                cover_path, message, input_format, use_compression, custom_delimiter=delimiter
            )

            p = Path(cover_path)
            default_out = str(p.with_stem(p.stem + "_payload").with_suffix(".png"))

            output_path, _ = QFileDialog.getSaveFileName(
                self.ui, "Save Stego Image", default_out, "PNG Image (*.png)"
            )
            if not output_path:
                return

            if not output_path.lower().endswith(".png"):
                output_path = output_path + ".png"

            if should_clean_metadata:
                if not metadata_cleaner.clean_metadata(cover_path, output_path):
                    raise RuntimeError("Failed to clean metadata.")
            else:
                try:
                    shutil.copy2(cover_path, output_path)
                except Exception as e:
                    raise RuntimeError(f"Failed to copy original file: {str(e)}")

            lsb.encode_text(
                image_path=output_path,
                output_path=output_path,
                text=message,
                input_format=input_format,
                use_compression=use_compression,
                custom_delimiter=delimiter,
                seed=seed
            )

            if seed:
                mode_info = "Non-Sequential LSB (Seed set)"
            else:
                mode_info = "Sequential LSB (Default Header set)"

            self.ui.pteEmbedMessage.clear()
            self._show_info("Success", f"Message hidden ({mode_info}) in:\n{output_path}")

            self._update_usage_display()

        except ValueError as ve:
            self._show_error("Validation Error", str(ve))
        except Exception as e:
            self._show_error("Process Failed", f"An error occurred: {str(e)}")

    """Runs upon extracting the payload - reads settings, calls lsb.decode_text"""
    def _extract_message(self):
        try:
            stego_path = self._require_file(self.ui.leStegoPath.text())

            if hasattr(self.ui, 'chkDebugDump'):
                if self.ui.chkDebugDump.isChecked():
                    self._perform_debug_dump(stego_path)
                    return

            extract_format = "utf-8"
            if hasattr(self.ui, 'cbExtractFormat'):
                extract_format = self.ui.cbExtractFormat.currentText().lower()

            extract_compression = False
            if hasattr(self.ui, 'chkExtractCompress'):
                extract_compression = self.ui.chkExtractCompress.isChecked()

            delimiter = self._get_delimiter(is_extract=True)
            seed = self._get_seed(is_extract=True)

            result = lsb.decode_text(
                image_path=stego_path,
                output_format=extract_format,
                use_compression=extract_compression,
                custom_delimiter=delimiter,
                seed=seed
            )

            if result:
                self.ui.tbExtractedMessage.setText(result)
                if hasattr(self.ui, 'chkAutoSave'):
                    if self.ui.chkAutoSave.isChecked():
                        self._save_text_with_dialog(result, stego_path)
            else:
                self.ui.tbExtractedMessage.clear()
                msg = "No hidden payload found."
                if delimiter:
                    msg = f"Custom Delimiter '{delimiter}' not found."
                if seed:
                    msg = msg + " (Make sure the correct seed is used!)"
                self._show_error("Extraction Failed", msg)

        except Exception as e:
            self._show_error("Error", str(e))

    """Calls lsb.debug_dump_raw"""
    def _perform_debug_dump(self, image_path):
        try:
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
                self._show_info("Debug Dump", "Raw bits extracted to text field.\n(Enable Autosave to save the full dump to a file)")

        except Exception as e:
            raise e

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

    def _show_error(self, title: str, message: str):
        QMessageBox.critical(self.ui, title, message)

    def _show_info(self, title: str, message: str):
        QMessageBox.information(self.ui, title, message)