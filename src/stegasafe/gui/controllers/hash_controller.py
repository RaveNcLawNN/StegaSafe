from pathlib import Path

from PyQt6.QtWidgets import QFileDialog, QMessageBox, QApplication

from stegasafe.core.crypto.hashing import hash_file, verify_file_hash
from stegasafe.utils.decorators import handle_ui_errors


class HashTabController:
    """Controller for the Hashes tab - handles hash computation and validation."""
    
    def __init__(self, ui):
        self.ui = ui
        
        self._populate_algorithms()
        self._wire_events()
    
    def _populate_algorithms(self):
        """Populate algorithm dropdowns with all FIPS 180-4 and FIPS 202 algorithms."""
        # FIPS 180-4: SHA-1 and SHA-2 families
        fips_180_4 = [
            "SHA-1",
            "SHA-224",
            "SHA-256",
            "SHA-384",
            "SHA-512",
            "SHA-512/224",
            "SHA-512/256"
        ]
        
        # FIPS 202: SHA-3 family
        fips_202 = [
            "SHA3-224",
            "SHA3-256",
            "SHA3-384",
            "SHA3-512",
            "SHAKE128",
            "SHAKE256"
        ]
        
        # Combine all algorithms
        algorithms = fips_180_4 + fips_202
        
        # Populate both algorithm dropdowns
        for cb in (self.ui.cbHashAlgo, self.ui.cbValidationHashAlgo):
            cb.clear()
            for algo in algorithms:
                cb.addItem(algo)
            # Set default to SHA-256
            cb.setCurrentText("SHA-256")
    
    def _wire_events(self):
        """Connect button clicks to their handler functions."""
        # Compute Hash section
        self.ui.btnBrowseHashFile.clicked.connect(
            lambda: self._choose_input_file(self.ui.leHashFile)
        )
        self.ui.pushButton.clicked.connect(self._compute_hash)  # Note: generic name in UI
        
        # Validate Hash section
        self.ui.btnValidationHashFile.clicked.connect(
            lambda: self._choose_input_file(self.ui.leValidationHashFile)
        )
        self.ui.btnExpectedHash.clicked.connect(self._validate_hash)
    
    def _choose_input_file(self, line_edit):
        """Open file dialog and set the selected file path."""
        path, _ = QFileDialog.getOpenFileName(self.ui, "Select File", "")
        if path:
            line_edit.setText(path)
    
    def _require_file(self, path_str: str) -> Path:
        """Validate that a file path exists and return Path object."""
        if not path_str:
            raise ValueError("No file selected.")
        p = Path(path_str)
        if not p.exists() or not p.is_file():
            raise ValueError("Selected file does not exist.")
        return p

    @handle_ui_errors
    def _compute_hash(self, *args):
        """Compute hash of selected file, display it, and copy to clipboard."""
        file_path = self._require_file(self.ui.leHashFile.text())
        algorithm_display = self.ui.cbHashAlgo.currentText()  # "SHA-256", "SHA-512", etc.
        # Pass the display name directly - hashing.py will normalize it
        algorithm = algorithm_display

        # Compute hash - errors here are now IntegrityError
        hash_value = hash_file(str(file_path), algorithm=algorithm)

        # Copy hash to clipboard automatically
        clipboard = QApplication.clipboard()
        clipboard.setText(hash_value)

        # Sync the validation algorithm dropdown
        self.ui.cbValidationHashAlgo.setCurrentText(algorithm_display)

        # Show success result
        QMessageBox.information(
            self.ui,
            "Hash Computed",
            f"Algorithm: {algorithm_display}\n\nHash:\n{hash_value}\n\n(Copied to clipboard - Validation algorithm set to match)"
        )

    @handle_ui_errors
    def _validate_hash(self, *args):
        """Validate file hash against expected hash."""
        file_path = self._require_file(self.ui.leValidationHashFile.text())
        algorithm_display = self.ui.cbValidationHashAlgo.currentText() # "SHA-256", "SHA-512", etc.
        # Pass the display name directly - hashing.py will normalize it
        algorithm = algorithm_display
        expected_hash = self.ui.leExpectedHash.text().strip()

        if not expected_hash:
            raise ValueError("Please enter an expected hash value.")

        # Get the algorithm from the compute section to check for mismatch
        compute_algorithm = self.ui.cbHashAlgo.currentText()
        
        # Verify hash
        is_valid = verify_file_hash(str(file_path), expected_hash, algorithm=algorithm)

        # Update result label styling
        if is_valid:
            self.ui.lblResult.setText(f"✓ Valid - Hash matches! (Algorithm: {algorithm_display})")
            self.ui.lblResult.setStyleSheet("color: green; font-weight: bold;")
        else:
            # Compute actual hash to show what it should be
            actual_hash = hash_file(str(file_path), algorithm=algorithm)
            self.ui.lblResult.setText(f"✗ Invalid - Hash does not match! (Algorithm: {algorithm_display})")
            self.ui.lblResult.setStyleSheet("color: red; font-weight: bold;")

            # Only show error popup if algorithms don't match (potential user error)
            # If algorithms match, hash mismatch is expected behavior (different files, etc.)
            if compute_algorithm != algorithm_display:
                QMessageBox.warning(
                    self.ui,
                    "Algorithm Mismatch",
                    f"The selected validation algorithm ({algorithm_display}) differs from the compute algorithm ({compute_algorithm}).\n\n"
                    f"Make sure you're using the same algorithm for both compute and validate.\n\n"
                    f"Expected hash: {expected_hash}\n"
                    f"Actual hash:   {actual_hash}"
                )