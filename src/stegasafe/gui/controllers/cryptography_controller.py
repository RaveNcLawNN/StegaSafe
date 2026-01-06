from pathlib import Path

from PyQt6.QtWidgets import QFileDialog, QMessageBox

from src.stegasafe.core.crypto.aes import AESCipher
from src.stegasafe.utils.file_adapter import read_bytes, write_bytes


class CryptoTabController:
    def __init__(self, ui, key_provider):
        self.ui = ui
        self.key_provider = key_provider

        self._populate_algorithms()
        self._populate_keys()
        self._wire_events()

    def refresh_keys(self):
        self._populate_keys()

    def _populate_algorithms(self):
        # Minimal for demo: only AES-GCM
        for cb in (self.ui.cbChooseEncAlgorithm, self.ui.cbChooseDecAlgorithm):
            cb.clear()
            cb.addItem("GCM")

    def _populate_keys(self):
        # Filter: symmetric AES keys only
        keys = self.key_provider.list_keys(kind="symmetric")
        keys = [k for k in keys if k.get("algorithm") == "AES"]

        for cb in (self.ui.cbChooseEncKey, self.ui.cbChooseDecKey):
            cb.clear()
            for k in keys:
                label = k["name"]
                if k.get("bits"):
                    label += f" ({k['bits']} bit)"
                cb.addItem(label, k["id"])  # store key_id as item data

    def _wire_events(self):
        self.ui.btnChooseFileToEncrypt.clicked.connect(
            lambda: self._choose_input_file(self.ui.leChooseFileToEncrypt)
        )
        self.ui.btnChooseFileToDecrypt.clicked.connect(
            lambda: self._choose_input_file(self.ui.leChooseFileToDecrypt)
        )

        self.ui.btnEncrypt.clicked.connect(self._encrypt)
        self.ui.btnDecrypt.clicked.connect(self._decrypt)

    def _choose_input_file(self, line_edit):
        path, _ = QFileDialog.getOpenFileName(self.ui, "Select File", "")
        if path:
            line_edit.setText(path)

    def _selected_key_bytes(self, combo_box) -> bytes:
        key_id = combo_box.currentData()
        if not key_id:
            raise ValueError("No key selected.")
        return self.key_provider.get_key_material(key_id)

    def _require_file(self, path_str: str, title: str) -> Path:
        if not path_str:
            raise ValueError("No file selected.")
        p = Path(path_str)
        if not p.exists() or not p.is_file():
            raise ValueError("Selected file does not exist.")
        return p

    def _show_error(self, title: str, message: str):
        QMessageBox.critical(self.ui, title, message)

    def _show_info(self, title: str, message: str):
        QMessageBox.information(self.ui, title, message)

    def _encrypt(self):
        try:
            in_path = self._require_file(self.ui.leChooseFileToEncrypt.text(), "Encrypt")
            mode = self.ui.cbChooseEncAlgorithm.currentText()
            key = self._selected_key_bytes(self.ui.cbChooseEncKey)

            default_out = str(in_path.with_suffix(in_path.suffix + ".enc"))
            out_path, _ = QFileDialog.getSaveFileName(self.ui, "Save Encrypted File", default_out)
            if not out_path:
                return

            plaintext = read_bytes(str(in_path))
            cipher = AESCipher(key)
            encrypted = cipher.encrypt(plaintext, mode=mode)

            write_bytes(out_path, encrypted)
            self._show_info("Encryption complete", f"Saved to:\n{out_path}")

        except Exception as e:
            self._show_error("Encryption failed", str(e))

    def _decrypt(self):
        try:
            in_path = self._require_file(self.ui.leChooseFileToDecrypt.text(), "Decrypt")
            mode = self.ui.cbChooseDecAlgorithm.currentText()
            key = self._selected_key_bytes(self.ui.cbChooseDecKey)

            # default output path suggestion
            if in_path.suffix == ".enc":
                default_out = in_path.with_suffix("")  # keeps .pdf, removes only .enc
            else:
                default_out = in_path.with_suffix(in_path.suffix + ".dec")

            out_path, _ = QFileDialog.getSaveFileName(
                self.ui,
                "Save Decrypted File",
                str(default_out),
                "All Files (*)"
            )
            if not out_path:
                return

            chosen = Path(out_path)
            if chosen.suffix == "":
                out_path = str(chosen.with_suffix(default_out.suffix))

            ciphertext = read_bytes(str(in_path))
            cipher = AESCipher(key)
            plaintext = cipher.decrypt(ciphertext, mode=mode)

            write_bytes(out_path, plaintext)
            self._show_info("Decryption complete", f"Saved to:\n{out_path}")

        except Exception as e:
            self._show_error("Decryption failed", str(e))
# test something