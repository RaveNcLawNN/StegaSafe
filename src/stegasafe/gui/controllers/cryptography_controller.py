from pathlib import Path
from PyQt6.QtWidgets import QFileDialog, QMessageBox

from stegasafe.core.crypto.aes import AESCipher
from stegasafe.core.crypto.chacha import ChaChaCipher, ChaChaStreamCipher
from stegasafe.core.crypto.hybrid import HybridCipher

from stegasafe.utils.file_adapter import read_bytes, write_bytes
from stegasafe.utils.decorators import handle_ui_errors
from stegasafe.utils.exceptions import ValidationError


class CryptoTabController:
    def __init__(self, ui, key_provider):
        self.ui = ui
        self.key_provider = key_provider

        self.ui.rbModeSym.setChecked(True)
        self.ui.rbDecModeSym.setChecked(True)

        self._populate_algorithms()
        self._populate_keys()
        self._wire_events()

    def refresh_keys(self):
        self._populate_keys()

    def _populate_algorithms(self):
        def fill_combo(combo, is_hybrid):
            combo.clear()
            if is_hybrid:
                combo.addItem("ECC (X25519 + AES-GCM)", "HYBRID")
            else:
                modes = ["GCM", "CBC", "CTR", "CFB", "OFB", "ECB"]
                for m in modes:
                    combo.addItem(f"AES-{m}", f"AES-{m}")

                # Beide Varianten anbieten
                combo.addItem("ChaCha20-Poly1305 (AEAD)", "CHACHA20")
                combo.addItem("ChaCha20 (Raw Stream)", "CHACHA20-STREAM")

                combo.setCurrentIndex(0)

        fill_combo(self.ui.cbChooseEncAlgorithm, self.ui.rbModeAsym.isChecked())
        fill_combo(self.ui.cbChooseDecAlgorithm, self.ui.rbDecModeAsym.isChecked())

    def _populate_keys(self, is_decrypt_refresh=None):
        """
        Füllt die Key-Boxen.
        is_decrypt_refresh: Wenn True, aktualisiere nur Decrypt-Box. Wenn None, beide.
        """

        # Check ob Vault offen ist
        if not (hasattr(self.key_provider, 'kv_controller') and self.key_provider.kv_controller.vault.is_unlocked):
            for cb in (self.ui.cbChooseEncKey, self.ui.cbChooseDecKey):
                cb.clear()
                cb.addItem("Unlock Vault to see keys...", None)
            return

        all_keys = self.key_provider.list_keys()

        # --- Helper zum Füllen ---
        def fill(combo, keys):
            combo.clear()
            if not keys:
                combo.addItem("No suitable keys found", None)
                return
            for k in keys:
                # Zeige Name + Bitgröße an
                label = f"{k['name']}"
                algo_info = k.get('algorithm', 'Unknown')
                if k.get('bits'):
                    label += f" ({k['bits']} bit)"
                else:
                    label += f" ({algo_info})"

                combo.addItem(label, k["id"])

        # --- Encrypt Tab Keys ---
        if is_decrypt_refresh is not True:  # Update Encrypt
            if self.ui.rbModeAsym.isChecked():
                # HYBRID: Wir brauchen PUBLIC Keys (X25519) des Empfängers
                filtered = [
                    k for k in all_keys
                    if str(k.get('algorithm', '')).upper() == "X25519"
                       and k.get('type') == "public"
                ]
            else:
                # SYMMETRISCH: Wir nehmen ALLE symmetrischen Keys.
                # Egal ob da "AES" steht. Ein AES-256 Key ist auch ein ChaCha20 Key.
                filtered = [
                    k for k in all_keys
                    if k.get('kind') == "symmetric" or k.get('type') == "symmetric"
                ]

            fill(self.ui.cbChooseEncKey, filtered)

        # --- Decrypt Tab Keys ---
        if is_decrypt_refresh is not False:  # Update Decrypt
            if self.ui.rbDecModeAsym.isChecked():
                # HYBRID: Wir brauchen UNSEREN PRIVATE Key (X25519)
                filtered = [
                    k for k in all_keys
                    if str(k.get('algorithm', '')).upper() == "X25519"
                       and k.get('type') == "private"
                ]
            else:
                # SYMMETRISCH
                filtered = [
                    k for k in all_keys
                    if k.get('kind') == "symmetric" or k.get('type') == "symmetric"
                ]

            fill(self.ui.cbChooseDecKey, filtered)

    def _wire_events(self):
        # File Dialogs
        self.ui.btnChooseFileToEncrypt.clicked.connect(lambda: self._choose_input_file(self.ui.leChooseFileToEncrypt))
        self.ui.btnChooseFileToDecrypt.clicked.connect(lambda: self._choose_input_file(self.ui.leChooseFileToDecrypt))

        # Actions
        self.ui.btnEncrypt.clicked.connect(self._encrypt)
        self.ui.btnDecrypt.clicked.connect(self._decrypt)

        # Radio Buttons (Mode Switch)
        self.ui.rbModeSym.toggled.connect(self._on_enc_mode_changed)
        self.ui.rbModeAsym.toggled.connect(self._on_enc_mode_changed)

        self.ui.rbDecModeSym.toggled.connect(self._on_dec_mode_changed)
        self.ui.rbDecModeAsym.toggled.connect(self._on_dec_mode_changed)

    def _on_enc_mode_changed(self):
        self._populate_algorithms()
        self._populate_keys(is_decrypt_refresh=False)

    def _on_dec_mode_changed(self):
        self._populate_algorithms()
        self._populate_keys(is_decrypt_refresh=True)

    def _choose_input_file(self, line_edit):
        path, _ = QFileDialog.getOpenFileName(self.ui, "Select File", "")
        if path:
            line_edit.setText(path)

    def _selected_key_bytes(self, combo_box) -> bytes:
        key_id = combo_box.currentData()
        if not key_id:
            raise ValidationError("No key selected (or Vault locked).")
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

        is_hybrid = self.ui.rbModeAsym.isChecked()
        key_bytes = self._selected_key_bytes(self.ui.cbChooseEncKey)
        algo_data = self.ui.cbChooseEncAlgorithm.currentData()

        # Dateiendung
        if is_hybrid:
            extension = ".enc"
        elif algo_data == "CHACHA20":
            extension = ".enc"
        elif algo_data == "CHACHA20-STREAM":
            extension = ".enc"
        else:
            extension = ".enc"

        default_out = str(in_path.with_suffix(in_path.suffix + extension))
        out_path, _ = QFileDialog.getSaveFileName(self.ui, "Save Encrypted File", default_out)
        if not out_path:
            return

        plaintext = read_bytes(str(in_path))
        encrypted_data = b""

        if is_hybrid:
            encrypted_data = HybridCipher.encrypt(plaintext, key_bytes)
        elif algo_data == "CHACHA20":
            cipher = ChaChaCipher(key_bytes)
            encrypted_data = cipher.encrypt(plaintext)
        elif algo_data == "CHACHA20-STREAM":
            cipher = ChaChaStreamCipher(key_bytes)
            encrypted_data = cipher.encrypt(plaintext)
        elif "AES" in algo_data:
            mode_str = algo_data.split("-")[1]
            cipher = AESCipher(key_bytes)
            encrypted_data = cipher.encrypt(plaintext, mode=mode_str)
        else:
            raise ValidationError("Unknown encryption algorithm selected.")

        write_bytes(out_path, encrypted_data)
        QMessageBox.information(self.ui, "Encryption complete", f"Saved to:\n{out_path}")

    @handle_ui_errors
    def _decrypt(self, *args):
        in_path = self._require_file(self.ui.leChooseFileToDecrypt.text())

        is_hybrid = self.ui.rbDecModeAsym.isChecked()
        key_bytes = self._selected_key_bytes(self.ui.cbChooseDecKey)
        algo_data = self.ui.cbChooseDecAlgorithm.currentData()

        if in_path.suffix in [".enc", ".cha", ".hyb"]:
            default_out = in_path.with_suffix("")
        else:
            default_out = in_path.with_suffix(in_path.suffix + ".dec")

        out_path, _ = QFileDialog.getSaveFileName(self.ui, "Save Decrypted File", str(default_out))
        if not out_path:
            return

        ciphertext = read_bytes(str(in_path))
        plaintext = b""

        if is_hybrid:
            plaintext = HybridCipher.decrypt(ciphertext, key_bytes)
        elif algo_data == "CHACHA20":
            cipher = ChaChaCipher(key_bytes)
            plaintext = cipher.decrypt(ciphertext)
        elif algo_data == "CHACHA20-STREAM":
            cipher = ChaChaStreamCipher(key_bytes)
            plaintext = cipher.decrypt(ciphertext)
        elif "AES" in algo_data:
            mode_str = algo_data.split("-")[1]
            cipher = AESCipher(key_bytes)
            plaintext = cipher.decrypt(ciphertext, mode=mode_str)
        else:
            raise ValidationError("Unknown decryption algorithm selected.")

        write_bytes(out_path, plaintext)
        QMessageBox.information(self.ui, "Decryption complete", f"Saved to:\n{out_path}")