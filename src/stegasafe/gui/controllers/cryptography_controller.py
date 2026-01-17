from pathlib import Path
from PyQt6.QtWidgets import QFileDialog, QMessageBox

# Importiere deine Cipher-Klassen
from src.stegasafe.core.crypto.aes import AESCipher
from src.stegasafe.core.crypto.chacha import ChaChaCipher
from src.stegasafe.core.crypto.hybrid import HybridCipher

from src.stegasafe.utils.file_adapter import read_bytes, write_bytes
from stegasafe.utils.decorators import handle_ui_errors
from stegasafe.utils.exceptions import ValidationError


class CryptoTabController:
    def __init__(self, ui, key_provider):
        self.ui = ui
        self.key_provider = key_provider

        # 1. Standard-Radio-Buttons setzen (falls im Designer nicht gesetzt)
        # Symmetrisch ist der Default
        self.ui.rbModeSym.setChecked(True)
        self.ui.rbDecModeSym.setChecked(True)

        self._populate_algorithms()
        self._populate_keys()
        self._wire_events()

    def refresh_keys(self):
        """Wird von außen aufgerufen, wenn sich der Vault-Status ändert"""
        self._populate_keys()

    def _populate_algorithms(self):
        """Füllt die Algo-Box basierend auf dem gewählten Modus (Sym vs. Hybrid)"""

        # Helper Funktion um Redundanz zwischen Encrypt/Decrypt Tab zu vermeiden
        def fill_combo(combo, is_hybrid):
            combo.clear()
            if is_hybrid:
                # S5/S6: Hybrid Mode (ECC + AES)
                # Wir speichern den technischen Key "HYBRID" in den UserData
                combo.addItem("ECC (X25519 + AES-GCM)", "HYBRID")
            else:
                # S2/S3: Symmetric Modes
                # AES
                modes = ["GCM", "CBC", "CTR", "CFB", "OFB", "ECB"]
                for m in modes:
                    combo.addItem(f"AES-{m}", f"AES-{m}")

                # ChaCha20
                combo.addItem("ChaCha20-Poly1305", "CHACHA20")

                # Default auf AES-GCM setzen
                combo.setCurrentIndex(0)

        # 1. Encrypt Tab Algorithmen
        fill_combo(self.ui.cbChooseEncAlgorithm, self.ui.rbModeAsym.isChecked())

        # 2. Decrypt Tab Algorithmen
        fill_combo(self.ui.cbChooseDecAlgorithm, self.ui.rbDecModeAsym.isChecked())

    def _populate_keys(self, is_decrypt_refresh=None):
        """
        Füllt die Key-Boxen.
        is_decrypt_refresh: Wenn True, aktualisiere nur Decrypt-Box (Performance). Wenn None, beide.
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
                # Zeige Name + Bitgröße an (z.B. "MyKey (256 bit)")
                label = f"{k['name']}"
                if k.get('bits'):
                    label += f" ({k['bits']} bit)"
                combo.addItem(label, k["id"])

        # --- Encrypt Tab Keys ---
        if is_decrypt_refresh is not True:  # Update Encrypt
            if self.ui.rbModeAsym.isChecked():
                # Hybrid: Wir brauchen PUBLIC Keys (X25519) des Empfängers
                filtered = [k for k in all_keys if k.get('algorithm') == "X25519" and k.get('type') == "public"]
            else:
                # Symmetrisch: AES oder ChaCha Keys
                # Annahme: ChaCha Keys haben 'algorithm': 'ChaCha20' oder 'AES' mit 256 bit
                filtered = [k for k in all_keys if k.get('type') == "symmetric"]

            fill(self.ui.cbChooseEncKey, filtered)

        # --- Decrypt Tab Keys ---
        if is_decrypt_refresh is not False:  # Update Decrypt
            if self.ui.rbDecModeAsym.isChecked():
                # Hybrid: Wir brauchen UNSEREN PRIVATE Key (X25519)
                filtered = [k for k in all_keys if k.get('algorithm') == "X25519" and k.get('type') == "private"]
            else:
                # Symmetrisch
                filtered = [k for k in all_keys if k.get('type') == "symmetric"]

            fill(self.ui.cbChooseDecKey, filtered)

    def _wire_events(self):
        # File Dialogs
        self.ui.btnChooseFileToEncrypt.clicked.connect(
            lambda: self._choose_input_file(self.ui.leChooseFileToEncrypt)
        )
        self.ui.btnChooseFileToDecrypt.clicked.connect(
            lambda: self._choose_input_file(self.ui.leChooseFileToDecrypt)
        )

        # Actions
        self.ui.btnEncrypt.clicked.connect(self._encrypt)
        self.ui.btnDecrypt.clicked.connect(self._decrypt)

        # Radio Buttons (Mode Switch)
        # Wenn wir umschalten, müssen sich die Algorithmen und die angezeigten Keys ändern
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
        # Der KeyProvider gibt uns die Raw Bytes (bei Sym) oder PEM Bytes (bei Asym)
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

        # 1. Modus & Key holen
        is_hybrid = self.ui.rbModeAsym.isChecked()
        key_bytes = self._selected_key_bytes(self.ui.cbChooseEncKey)
        algo_data = self.ui.cbChooseEncAlgorithm.currentData()  # z.B. "AES-GCM" oder "CHACHA20"

        # 2. Dateiendung & Cipher bestimmen
        if is_hybrid:
            extension = ".hyb"
        elif algo_data == "CHACHA20":
            extension = ".cha"
        else:
            extension = ".enc"

        default_out = str(in_path.with_suffix(in_path.suffix + extension))
        out_path, _ = QFileDialog.getSaveFileName(self.ui, "Save Encrypted File", default_out)

        if not out_path:
            return

        plaintext = read_bytes(str(in_path))
        encrypted_data = b""

        # 3. Verschlüsseln
        if is_hybrid:
            # S5: Hybrid Encryption (Key ist Public Key PEM)
            encrypted_data = HybridCipher.encrypt(plaintext, key_bytes)

        elif algo_data == "CHACHA20":
            # S2: ChaCha20
            cipher = ChaChaCipher(key_bytes)
            encrypted_data = cipher.encrypt(plaintext)

        elif "AES" in algo_data:
            # Standard AES (z.B. AES-GCM)
            mode_str = algo_data.split("-")[1]  # "AES-CBC" -> "CBC"
            cipher = AESCipher(key_bytes)
            encrypted_data = cipher.encrypt(plaintext, mode=mode_str)

        else:
            raise ValidationError("Unknown encryption algorithm selected.")

        write_bytes(out_path, encrypted_data)
        QMessageBox.information(self.ui, "Encryption complete", f"Saved to:\n{out_path}")

    @handle_ui_errors
    def _decrypt(self, *args):
        in_path = self._require_file(self.ui.leChooseFileToDecrypt.text())

        # 1. Modus & Key holen
        is_hybrid = self.ui.rbDecModeAsym.isChecked()
        key_bytes = self._selected_key_bytes(self.ui.cbChooseDecKey)
        algo_data = self.ui.cbChooseDecAlgorithm.currentData()

        # 2. Output Pfad raten (Endung entfernen)
        if in_path.suffix in [".enc", ".cha", ".hyb"]:
            default_out = in_path.with_suffix("")
        else:
            default_out = in_path.with_suffix(in_path.suffix + ".dec")

        out_path, _ = QFileDialog.getSaveFileName(self.ui, "Save Decrypted File", str(default_out))

        if not out_path:
            return

        ciphertext = read_bytes(str(in_path))
        plaintext = b""

        # 3. Entschlüsseln
        if is_hybrid:
            # S6: Hybrid Decrypt (Key ist Private Key PEM)
            # Hinweis: Falls Private Key passwortgeschützt ist, müsste das hier handled werden.
            # Wir gehen davon aus, dass get_key_material() uns den unverschlüsselten PEM gibt
            # (weil der Vault entsperrt ist).
            plaintext = HybridCipher.decrypt(ciphertext, key_bytes)

        elif algo_data == "CHACHA20":
            # ChaCha20
            cipher = ChaChaCipher(key_bytes)
            plaintext = cipher.decrypt(ciphertext)

        elif "AES" in algo_data:
            # AES
            mode_str = algo_data.split("-")[1]
            cipher = AESCipher(key_bytes)
            plaintext = cipher.decrypt(ciphertext, mode=mode_str)

        else:
            raise ValidationError("Unknown decryption algorithm selected.")

        write_bytes(out_path, plaintext)
        QMessageBox.information(self.ui, "Decryption complete", f"Saved to:\n{out_path}")