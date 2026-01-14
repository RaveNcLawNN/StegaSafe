from pathlib import Path

from PyQt6.QtWidgets import QFileDialog, QMessageBox, QApplication

from src.stegasafe.core.crypto.hashing import hash_file, verify_file_hash


class HashTabController:
    """Controller for the Hashes tab - handles hash computation and validation."""
    
    def __init__(self, ui):
        self.ui = ui
        
        self._populate_algorithms()
        self._wire_events()
    
    def _populate_algorithms(self):
        """Populate algorithm dropdowns with common hash algorithms."""
        algorithms = ["SHA-256", "SHA-512", "SHA-1", "MD5"]
        
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
    
    def _show_error(self, title: str, message: str):
        """Display an error message dialog."""
        QMessageBox.critical(self.ui, title, message)
    
    def _show_info(self, title: str, message: str):
        """Display an information message dialog."""
        QMessageBox.information(self.ui, title, message)
    
    def _compute_hash(self):
        """Compute hash of selected file, display it, and copy to clipboard."""
        try:
            file_path = self._require_file(self.ui.leHashFile.text())
            algorithm_display = self.ui.cbHashAlgo.currentText()  # "SHA-256", "SHA-512", etc.
            algorithm = algorithm_display.lower().replace("-", "")  # "SHA-256" -> "sha256"
            
            # Compute hash
            hash_value = hash_file(str(file_path), algorithm=algorithm)
            
            # Copy hash to clipboard automatically
            clipboard = QApplication.clipboard()
            clipboard.setText(hash_value)
            
            # Also sync the validation algorithm dropdown to match (so user doesn't forget)
            self.ui.cbValidationHashAlgo.setCurrentText(algorithm_display)
            
            # Show result in a message box (hash is already copied to clipboard)
            self._show_info(
                "Hash Computed",
                f"Algorithm: {algorithm_display}\n\nHash:\n{hash_value}\n\n(Copied to clipboard - Validation algorithm set to match)"
            )
        
        except Exception as e:
            self._show_error("Hash Computation Failed", str(e))
    
    def _validate_hash(self):
        """Validate file hash against expected hash."""
        try:
            file_path = self._require_file(self.ui.leValidationHashFile.text())
            algorithm_display = self.ui.cbValidationHashAlgo.currentText()  # "SHA-256", "SHA-512", etc.
            algorithm = algorithm_display.lower().replace("-", "")  # "SHA-256" -> "sha256"
            expected_hash = self.ui.leExpectedHash.text().strip()
            
            if not expected_hash:
                raise ValueError("Please enter an expected hash value.")
            
            # Verify hash
            is_valid = verify_file_hash(str(file_path), expected_hash, algorithm=algorithm)
            
            # Update result label
            if is_valid:
                self.ui.lblResult.setText(f"✓ Valid - Hash matches! (Algorithm: {algorithm_display})")
                self.ui.lblResult.setStyleSheet("color: green; font-weight: bold;")
            else:
                # Compute actual hash to show what it should be (for debugging)
                actual_hash = hash_file(str(file_path), algorithm=algorithm)
                self.ui.lblResult.setText(f"✗ Invalid - Hash does not match! (Algorithm: {algorithm_display})")
                self.ui.lblResult.setStyleSheet("color: red; font-weight: bold;")
                # Show helpful error with actual hash
                self._show_error(
                    "Hash Validation Failed",
                    f"Hash does not match!\n\nAlgorithm: {algorithm_display}\nExpected: {expected_hash}\nActual:   {actual_hash}\n\nMake sure you're using the same algorithm for both compute and validate."
                )
        
        except Exception as e:
            self.ui.lblResult.setText("Error")
            self.ui.lblResult.setStyleSheet("color: red;")
            self._show_error("Hash Validation Failed", str(e))
