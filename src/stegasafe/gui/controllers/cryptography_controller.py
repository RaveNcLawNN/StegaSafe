from pathlib import Path
from PyQt6.QtWidgets import QFileDialog, QMessageBox

from src.stegasafe.core.crypto.aes import AESCipher
from src.stegasafe.utils.file_adapter import read_bytes, write_bytes

class CryptoTabController:
    def __init__(self, ui, key_provider):
        """
        Constructor: Bridges the UI with the Cryptographic backend.
        - Injection: Uses 'key_provider' to access authorized keys without
          needing direct access to the Vault storage.
        - Initialization: Pre-loads supported algorithms and existing keys.
        """
        self.ui = ui
        self.key_provider = key_provider

        self._populate_algorithms()
        self._populate_keys()
        self._wire_events()

    def refresh_keys(self):
        """
        Observer Interface: Re-syncs the key list.
        - Public method called by MainWindowController whenever the Vault
          is updated or unlocked.
        """
        self._populate_keys()

    def _populate_algorithms(self):
        """Standardization: Defines supported encryption modes (e.g., AES-GCM)."""
        for cb in (self.ui.cbChooseEncAlgorithm, self.ui.cbChooseDecAlgorithm):
            cb.clear()
            cb.addItem("GCM")

    def _populate_keys(self):
        """
        UI Filtering: Populates dropdowns with compatible keys only.
        - Filters the provider for 'symmetric' 'AES' keys to prevent
          using asymmetric keys for symmetric operations.
        - Stores key_id as internal metadata (ItemDataRole) to decouple
          UI labels from actual key identifiers.
        """
        keys = self.key_provider.list_keys(kind="symmetric")
        keys = [k for k in keys if k.get("algorithm") == "AES"]

        for cb in (self.ui.cbChooseEncKey, self.ui.cbChooseDecKey):
            cb.clear()
            for k in keys:
                label = k["name"]
                if k.get("bits"):
                    label += f" ({k['bits']} bit)"
                cb.addItem(label, k["id"])

    def _wire_events(self):
        """Connects file dialogs and process buttons."""
        self.ui.btnChooseFileToEncrypt.clicked.connect(
            lambda: self._choose_input_file(self.ui.leChooseFileToEncrypt)
        )
        self.ui.btnChooseFileToDecrypt.clicked.connect(
            lambda: self._choose_input_file(self.ui.leChooseFileToDecrypt)
        )
        self.ui.btnEncrypt.clicked.connect(self._encrypt)
        self.ui.btnDecrypt.clicked.connect(self._decrypt)

    def _choose_input_file(self, line_edit):
        """NFR3 Helper: Implements mouse-only file selection via QFileDialog."""
        path, _ = QFileDialog.getOpenFileName(self.ui, "Select File", "")
        if path:
            line_edit.setText(path)

    def _selected_key_bytes(self, combo_box) -> bytes:
        """Data Retrieval: Fetches raw key material based on UI selection."""
        key_id = combo_box.currentData()
        if not key_id:
            raise ValueError("No key selected.")
        return self.key_provider.get_key_material(key_id)

    def _require_file(self, path_str: str, title: str) -> Path:
        """Ensures the target file exists before attempting IO."""
        if not path_str:
            raise ValueError("No file selected.")
        p = Path(path_str)
        if not p.exists() or not p.is_file():
            raise ValueError("Selected file does not exist.")
        return p

    def _encrypt(self):
        """
        Encryption Workflow:
        - Mode: Uses AES-GCM for authenticated encryption.
        - IO Safety: Suggests an '.enc' extension to prevent overwriting originals.
        - Atomicity: Operations are performed in memory before writing
          to disk to ensure partial files aren't created on failure.
        """
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
            QMessageBox.information(self.ui, "Success", f"File encrypted:\n{out_path}")

        except Exception as e:
            QMessageBox.critical(self.ui, "Encryption failed", str(e))

    def _decrypt(self):
        """
        Decryption Workflow:
        - Automatically handles '.enc' suffix removal for output naming.
        - Verification: GCM mode ensures the file hasn't been tampered with.
        """
        try:
            in_path = self._require_file(self.ui.leChooseFileToDecrypt.text(), "Decrypt")
            mode = self.ui.cbChooseDecAlgorithm.currentText()
            key = self._selected_key_bytes(self.ui.cbChooseDecKey)

            # Suggest output path (strip .enc if present)
            default_out = in_path.with_suffix("") if in_path.suffix == ".enc" else in_path.with_suffix(in_path.suffix + ".dec")

            out_path, _ = QFileDialog.getSaveFileName(self.ui, "Save Decrypted File", str(default_out))
            if not out_path:
                return

            ciphertext = read_bytes(str(in_path))
            cipher = AESCipher(key)
            plaintext = cipher.decrypt(ciphertext, mode=mode)

            write_bytes(out_path, plaintext)
            QMessageBox.information(self.ui, "Success", f"File decrypted:\n{out_path}")

        except Exception as e:
            QMessageBox.critical(self.ui, "Decryption failed", str(e))