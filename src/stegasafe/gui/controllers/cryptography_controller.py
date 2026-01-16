from pathlib import Path
from PyQt6.QtWidgets import QFileDialog, QMessageBox
from src.stegasafe.core.crypto.aes import AESCipher
from src.stegasafe.utils.file_adapter import read_bytes, write_bytes
from stegasafe.utils.decorators import handle_ui_errors
from stegasafe.utils.exceptions import ValidationError

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
        modes = ["GCM", "CBC", "CTR", "CFB", "OFB", "ECB"]
        for cb in (self.ui.cbChooseEncAlgorithm, self.ui.cbChooseDecAlgorithm):
            cb.clear()
            cb.addItems(modes)
            cb.setCurrentText("GCM")

    def _populate_keys(self):
        if hasattr(self.key_provider, 'kv_controller') and self.key_provider.kv_controller.vault.is_unlocked:
            keys = self.key_provider.list_keys(kind="symmetric")
            keys = [k for k in keys if k.get("algorithm") == "AES"]
            for cb in (self.ui.cbChooseEncKey, self.ui.cbChooseDecKey):
                cb.clear()
                for k in keys:
                    label = f"{k['name']} ({k.get('bits', '-')} bit)"
                    cb.addItem(label, k["id"])
        else:
            for cb in (self.ui.cbChooseEncKey, self.ui.cbChooseDecKey):
                cb.clear()
                cb.addItem("Unlock Vault to see keys...")

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
            raise ValidationError("No key selected.")
        return self.key_provider.get_key_material(key_id)

    def _require_file(self, path_str: str) -> Path:
        if not path_str:
            raise ValidationError("No file selected.")
        p = Path(path_str)
        if not p.exists() or not p.is_file():
            raise ValidationError("Selected file does not exist.")
        return p

    @handle_ui_errors
    def _encrypt(self, *args):
        in_path = self._require_file(self.ui.leChooseFileToEncrypt.text())
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
        QMessageBox.information(self.ui, "Encryption complete", f"Saved to:\n{out_path}")

    @handle_ui_errors
    def _decrypt(self, *args):
        in_path = self._require_file(self.ui.leChooseFileToDecrypt.text())
        mode = self.ui.cbChooseDecAlgorithm.currentText()
        key = self._selected_key_bytes(self.ui.cbChooseDecKey)

        if in_path.suffix == ".enc":
            default_out = in_path.with_suffix("")
        else:
            default_out = in_path.with_suffix(in_path.suffix + ".dec")

        out_path, _ = QFileDialog.getSaveFileName(self.ui, "Save Decrypted File", str(default_out))

        if not out_path:
            return

        ciphertext = read_bytes(str(in_path))
        cipher = AESCipher(key)
        # decryption fails here if key is wrong, raising CryptographyError
        plaintext = cipher.decrypt(ciphertext, mode=mode)

        write_bytes(out_path, plaintext)
        QMessageBox.information(self.ui, "Decryption complete", f"Saved to:\n{out_path}")