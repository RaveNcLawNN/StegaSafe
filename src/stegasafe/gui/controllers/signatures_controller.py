from pathlib import Path
from PyQt6.QtWidgets import QFileDialog, QMessageBox, QApplication
from PyQt6.QtCore import Qt

from stegasafe.core.crypto.signatures import sign_file, verify_file_signature
from stegasafe.utils.decorators import handle_ui_errors


class SignatureTabController:
    # Supported signature algorithms
    SUPPORTED_ALGORITHMS = ["Ed25519", "RSA"]
    STATUS_STYLE_VALID = "color: green; font-weight: bold;"
    STATUS_STYLE_INVALID = "color: red; font-weight: bold;"

    def __init__(self, ui, key_provider):
        self.ui = ui
        self.key_provider = key_provider

        self._initialize_ui_state()
        self._wire_events()

    def _initialize_ui_state(self):
        """Sets the initial state of UI components."""
        self.ui.pbSign.setValue(0)
        self.ui.pbVerification.setValue(0)
        self._populate_key_dropdowns()

    def refresh_keys(self):
        """Public method to trigger a refresh when the vault state changes."""
        self._populate_key_dropdowns()

    def _populate_key_dropdowns(self):
        """Filters and loads signature-capable keys (RSA and Ed25519) or shows helpful placeholders based on state."""
        # 1. Check if the vault is accessible
        is_vault_unlocked = (hasattr(self.key_provider, 'kv_controller') and
                             self.key_provider.kv_controller.vault.is_unlocked)

        if not is_vault_unlocked:
            self._set_ui_placeholders("Unlock Vault to see keys...")
            return

        # 2. Vault is open, fetch and filter keys (RSA and Ed25519 are signature-capable)
        all_keys = self.key_provider.list_keys()
        private_keys = [k for k in all_keys if
                        k.get("algorithm") in self.SUPPORTED_ALGORITHMS and k.get("role") == "private"]
        public_keys = [k for k in all_keys if 
                       k.get("algorithm") in self.SUPPORTED_ALGORITHMS and k.get("role") == "public"]

        # 3. Populate Private Keys or show 'Empty' placeholder
        if not private_keys:
            self.ui.cbSigPrivKSelection.clear()
            self.ui.cbSigPrivKSelection.addItem("Add RSA or Ed25519 private key to enable signing")
        else:
            self._update_combo_box(self.ui.cbSigPrivKSelection, private_keys)

        # 4. Populate Public Keys or show 'Empty' placeholder
        if not public_keys:
            self.ui.cbSigPubKSelection.clear()
            self.ui.cbSigPubKSelection.addItem("Add RSA or Ed25519 public key to enable verification")
        else:
            self._update_combo_box(self.ui.cbSigPubKSelection, public_keys)

    def _set_ui_placeholders(self, message):
        """Helper to set a uniform message across all signature dropdowns."""
        for cb in (self.ui.cbSigPrivKSelection, self.ui.cbSigPubKSelection):
            cb.clear()
            cb.addItem(message)

    def _update_combo_box(self, combo_box, keys):
        """Helper to clear and fill a specific combo box with key metadata."""
        combo_box.clear()
        for key_metadata in keys:
            algorithm = key_metadata.get("algorithm", "Unknown")
            # For RSA keys, include bit size if available
            if algorithm == "RSA" and key_metadata.get("bits"):
                label = f"{key_metadata['name']} (RSA-{key_metadata['bits']})"
            else:
                label = f"{key_metadata['name']} ({algorithm})"
            combo_box.addItem(label, key_metadata["id"])

    def _wire_events(self):
        """Connects UI signals to controller slots."""
        # File Selection
        self.ui.btnChooseFileToSign.clicked.connect(lambda: self._handle_file_browsing(self.ui.leChooseFileToSign))
        self.ui.btnChooseFileToVerify.clicked.connect(lambda: self._handle_file_browsing(self.ui.leChooseFileToVerify))

        # Execution Actions
        self.ui.btnSigPrivKSelection.clicked.connect(self._execute_signing_process)
        self.ui.btnSigPubKSelection.clicked.connect(self._execute_verification_process)

        # Utilities
        self.ui.btnCopySignature.clicked.connect(self._copy_signature_to_clipboard)

    def _handle_file_browsing(self, path_display_widget):
        """Opens a file dialog and updates the corresponding QLineEdit."""
        selected_path, _ = QFileDialog.getOpenFileName(self.ui, "Select File", "")
        if selected_path:
            path_display_widget.setText(selected_path)

    def _copy_signature_to_clipboard(self):
        """Transfers the generated signature text to the system clipboard."""
        signature_text = self.ui.leShowSignature.text().strip()
        if signature_text:
            QApplication.clipboard().setText(signature_text)
            QMessageBox.information(self.ui, "Clipboard", "Signature successfully copied.")

    @handle_ui_errors
    def _execute_signing_process(self, *args):
        self.ui.pbSign.setValue(10)

        target_file = self.ui.leChooseFileToSign.text()
        key_id = self.ui.cbSigPrivKSelection.currentData()

        if not target_file or not key_id:
            # The decorator will catch this and show a "System Error" (ValueError)
            raise ValueError("Both a file and a private key (RSA or Ed25519) must be selected.")

        self.ui.pbSign.setValue(30)
        private_key_pem = self.key_provider.get_key_material(key_id)

        self.ui.pbSign.setValue(60)
        # If sign_file fails, it raises a SignatureError which the decorator
        # displays with the title "Signature Error".
        signature_bytes = sign_file(target_file, private_key_pem)

        # Update UI with the resulting hex string
        self.ui.leShowSignature.setText(signature_bytes.hex())
        self.ui.pbSign.setValue(100)

    @handle_ui_errors
    def _execute_verification_process(self, *args):
        self.ui.pbVerification.setValue(10)

        target_file = self.ui.leChooseFileToVerify.text()
        signature_hex = self.ui.leShowSignature_2.text().strip()
        key_id = self.ui.cbSigPubKSelection.currentData()

        if not all([target_file, signature_hex, key_id]):
            # Reset UI state before raising error
            self.ui.pbVerification.setValue(0)
            self.ui.lblFileValiditShow.setText("")
            raise ValueError("Required fields missing: File, Signature, or Public Key.")

        self.ui.pbVerification.setValue(40)
        public_key_pem = self.key_provider.get_key_material(key_id)

        try:
            signature_bytes = bytes.fromhex(signature_hex)
        except ValueError:
            # Reset UI state before raising error
            self.ui.pbVerification.setValue(0)
            self.ui.lblFileValiditShow.setText("")
            raise ValueError("The provided signature is not valid hexadecimal text.")

        self.ui.pbVerification.setValue(70)
        is_authentic = verify_file_signature(target_file, signature_bytes, public_key_pem)

        self._display_verification_result(is_authentic)
        self.ui.pbVerification.setValue(100)

    def _display_verification_result(self, is_authentic):
        """Updates the result label with appropriate text and styling."""
        label = self.ui.lblFileValiditShow
        if is_authentic:
            label.setText("✓ SIGNATURE VALID")
            label.setStyleSheet(self.STATUS_STYLE_VALID)
        else:
            label.setText("✗ SIGNATURE INVALID")
            label.setStyleSheet(self.STATUS_STYLE_INVALID)