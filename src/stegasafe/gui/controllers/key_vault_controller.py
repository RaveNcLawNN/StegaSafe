from pathlib import Path
from PyQt6.QtWidgets import QMessageBox, QTreeWidgetItem, QLineEdit, QFileDialog, QInputDialog
from PyQt6.QtCore import Qt

from stegasafe.core.vault.manager import KeyVault
from stegasafe.core.crypto.key_import import detect_and_validate_key
from stegasafe.utils.decorators import handle_ui_errors
from stegasafe.utils import read_bytes, write_bytes


class KeyVaultController:
    def __init__(self, ui, vault_path: str, on_keys_changed=None):
        self.ui = ui
        self.vault = KeyVault(vault_path)
        self.vault_password = None
        self.on_keys_changed = on_keys_changed
        self.vault_path = vault_path

        # Set password field to password mode (obfuscate input)
        self.ui.leVaultPassword.setEchoMode(QLineEdit.EchoMode.Password)

        self.ui.swKeyVault.setCurrentWidget(self.ui.pgePassword)

        # Set up the status label to show welcome message if vault doesn't exist
        self._update_status_message()

        self._wire_events()

        self.ui.twKeys.itemSelectionChanged.connect(self._on_key_selected)
        self._keys_cache = {}

    def _update_status_message(self):
        """Update the status label to show welcome message if vault doesn't exist, or locked message if it does."""
        if not Path(self.vault_path).exists():
            # First-time use - show welcome message
            welcome_text = (
                "Welcome to StegaSafe Key Vault!\n\n"
                "This is your first time using the Key Vault. Please enter a master password below.\n\n"
                "This password will be used to:\n"
                "• Encrypt and protect all your cryptographic keys\n"
                "• Unlock the vault each time you start the application\n\n"
                "⚠️ Important: Remember this password! If you forget it, you will not be able to access your keys.\n\n"
                "The vault will be created automatically when you click 'Unlock'."
            )
            self.ui.lblVaultStatus.setText(welcome_text)
            self.ui.lblVaultStatus.setWordWrap(True)  # Enable word wrap for multi-line text
        else:
            # Existing vault - show standard locked message
            self.ui.lblVaultStatus.setText("The Key Vault is locked. Enter Password to unlock.")
            self.ui.lblVaultStatus.setWordWrap(False)
    
    def on_tab_selected(self):
        """Called when the Key Vault tab is selected. Updates status message if needed."""
        self._update_status_message()

    def _wire_events(self):
        self.ui.btnUnlockVault.clicked.connect(self._unlock_vault)
        self.ui.btnDelete.clicked.connect(self._delete_key)
        self.ui.btnRename.clicked.connect(self._rename_key)
        self.ui.btnImport.clicked.connect(self._import_key)
        self.ui.btnExport.clicked.connect(self._export_key)

    @handle_ui_errors
    def _unlock_vault(self, *args):
        password = self.ui.leVaultPassword.text()
        if not password:
            raise ValueError("Please enter a vault password.")

        was_reset, message = self.vault.unlock(password)
        self.vault_password = password

        self.ui.leVaultPassword.clear()
        self._show_unlocked_ui()
        self.refresh_keys()

        if self.on_keys_changed:
            self.on_keys_changed()

        # Show message if vault was reset (corrupted) or newly created
        if was_reset:
            QMessageBox.information(
                self.ui,
                "Vault Reset",
                f"{message}\n\nYou can now add keys to the new vault."
            )
        elif "New vault created" in message:
            QMessageBox.information(
                self.ui,
                "Vault Created",
                "Your Key Vault has been created successfully!\n\n"
                "You can now generate and store cryptographic keys.\n\n"
                "Remember: You'll need to enter this password each time you unlock the vault."
            )

    def _show_unlocked_ui(self):
        self.ui.swKeyVault.setCurrentWidget(self.ui.pgeUnlocked)

    @handle_ui_errors
    def refresh_keys(self, *args):
        keys = self.vault.list_keys()
        self._keys_cache = {k["id"]: k for k in keys}
        self._populate_tree(keys)
        self._clear_details()

    def _populate_tree(self, keys):
        tree = self.ui.twKeys
        tree.clear()

        for k in keys:
            label = k["name"]

            item = QTreeWidgetItem([label])
            item.setData(0, Qt.ItemDataRole.UserRole, k["id"])
            tree.addTopLevelItem(item)

    def _on_key_selected(self):
        items = self.ui.twKeys.selectedItems()
        if not items:
            self._clear_details()
            return

        key_id = items[0].data(0, Qt.ItemDataRole.UserRole)
        if not key_id:
            self._clear_details()
            return

        meta = self._keys_cache.get(key_id)
        if not meta:
            self._clear_details()
            return

        self._show_details(meta)

    def _show_details(self, meta: dict):
        self.ui.leSelectedKey.setEnabled(True)
        self.ui.leSelectedKey.setReadOnly(False)
        self.ui.leSelectedKey.setText(meta.get("name", ""))

        # self.ui.lblKeyName.setText(meta.get("name", "-"))
        self.ui.lblKeyType.setText(meta.get("kind", "-"))
        self.ui.lblKeyAlgorithms.setText(meta.get("algorithm", "-"))
        self.ui.lblKeyVisibility.setText(meta.get("role", "symmetric/none") if meta.get("role") else "n/a")
        self.ui.lblKeyID.setText(meta.get("id", "-"))
        self.ui.lblKeyLength.setText(str(meta.get("bits", "-")))
        self.ui.lblKeySize.setText("-")  # keep placeholder unless you define what “size” means

    def _clear_details(self):
        self.ui.leSelectedKey.setReadOnly(True)  # Make read-only when no key selected
        self.ui.leSelectedKey.clear()

        self.ui.lblKeyName.setText("-")
        self.ui.lblKeyType.setText("-")
        self.ui.lblKeyAlgorithms.setText("-")
        self.ui.lblKeyVisibility.setText("-")
        self.ui.lblKeyID.setText("-")
        self.ui.lblKeyLength.setText("-")
        self.ui.lblKeySize.setText("-")

    def _get_selected_key_id(self):
        """Get the ID of the currently selected key, or None if none selected."""
        items = self.ui.twKeys.selectedItems()
        if not items:
            return None
        return items[0].data(0, Qt.ItemDataRole.UserRole)

    @handle_ui_errors
    def _delete_key(self, *args):
        """Delete the currently selected key."""
        key_id = self._get_selected_key_id()
        if not key_id:
            raise ValueError("Please select a key to delete.")

        reply = QMessageBox.question(
            self.ui,
            "Confirm Delete",
            f"Are you sure you want to delete this key?\n\nThis action cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        # If vault_password is None, manager.py will now throw a VaultError
        # which the decorator catches.
        self.vault.delete_key(key_id, self.vault_password)
        self.refresh_keys()

        if self.on_keys_changed:
            self.on_keys_changed()

        QMessageBox.information(self.ui, "Key Deleted", "Key has been deleted successfully.")

    @handle_ui_errors
    def _rename_key(self, *args):
        """Rename the currently selected key."""
        key_id = self._get_selected_key_id()
        if not key_id:
            raise ValueError("Please select a key to rename.")

        new_name = self.ui.leSelectedKey.text().strip()
        if not new_name:
            raise ValueError("Please enter a new name for the key.")

        self.vault.rename_key(key_id, new_name, self.vault_password)
        self.refresh_keys()

        if self.on_keys_changed:
            self.on_keys_changed()

        QMessageBox.information(self.ui, "Key Renamed", "Key has been renamed successfully.")

    @handle_ui_errors
    def _import_key(self, *args):
        """Import an external key file into the vault."""
        if not self.vault.is_unlocked:
            raise ValueError("Please unlock the vault before importing keys.")
        
        # Open file dialog to select key file
        file_path, _ = QFileDialog.getOpenFileName(
            self.ui,
            "Import Key File",
            "",
            "All Files (*);;PEM Files (*.pem);;Key Files (*.key)"
        )
        
        if not file_path:
            return
        
        try:
            # Read and validate the key file
            file_contents = read_bytes(file_path)
            key_kind, key_bytes, algorithm, role, bit_size = detect_and_validate_key(file_contents)
            
            # Get key name from user
            key_name, ok = QInputDialog.getText(
                self.ui,
                "Import Key",
                f"Enter a name for this key:\n\n"
                f"Type: {key_kind}\n"
                f"Algorithm: {algorithm}\n"
                f"Role: {role if role else 'N/A'}\n"
                f"Size: {bit_size if bit_size else 'N/A'} bits",
                text=f"Imported {algorithm} key"
            )
            
            if not ok or not key_name.strip():
                return
            
            key_name = key_name.strip()
            
            # For asymmetric keys, add role suffix if not already present
            if key_kind == "asymmetric" and role:
                if role not in key_name.lower():
                    key_name = f"{key_name} ({role})"
            
            # Store the key in the vault
            self.vault.add_key(
                name=key_name,
                kind=key_kind,
                algorithm=algorithm,
                material=key_bytes,
                password=self.vault_password,
                role=role,
                bits=bit_size
            )
            
            # Refresh the key list
            self.refresh_keys()
            
            if self.on_keys_changed:
                self.on_keys_changed()
            
            QMessageBox.information(
                self.ui,
                "Key Imported",
                f"Key '{key_name}' has been successfully imported and stored in the vault."
            )
        except Exception as e:
            # Re-raise to be caught by handle_ui_errors decorator
            raise

    @handle_ui_errors
    def _export_key(self, *args):
        """Export a key from the vault to a file."""
        if not self.vault.is_unlocked:
            raise ValueError("Please unlock the vault before exporting keys.")
        
        key_id = self._get_selected_key_id()
        if not key_id:
            raise ValueError("Please select a key to export.")
        
        # Get key metadata
        key_meta = self._keys_cache.get(key_id)
        if not key_meta:
            raise ValueError("Selected key not found.")
        
        # Get key material
        key_bytes = self.vault.get_key_material(key_id)
        
        # Determine default filename and file filter based on key type
        key_name = key_meta.get("name", "key")
        algorithm = key_meta.get("algorithm", "").lower()
        kind = key_meta.get("kind", "")
        role = key_meta.get("role", "")
        
        if kind == "asymmetric":
            # Asymmetric keys are already in PEM format
            if "private" in role.lower():
                default_filename = f"{key_name}_private.pem"
                file_filter = "PEM Files (*.pem);;All Files (*)"
            else:
                default_filename = f"{key_name}_public.pem"
                file_filter = "PEM Files (*.pem);;All Files (*)"
        else:
            # Symmetric keys - export as raw bytes or hex
            default_filename = f"{key_name}.key"
            file_filter = "Key Files (*.key);;Hex Files (*.hex);;All Files (*)"
        
        # Open save dialog
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self.ui,
            "Export Key",
            default_filename,
            file_filter
        )
        
        if not file_path:
            return
        
        # Write the key file
        if kind == "asymmetric":
            # Write PEM directly
            write_bytes(file_path, key_bytes)
        else:
            # Symmetric key - check if user wants hex format
            if selected_filter and "hex" in selected_filter.lower():
                # Export as hex text file
                hex_str = key_bytes.hex()
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(hex_str)
            else:
                # Export as raw binary
                write_bytes(file_path, key_bytes)
        
        QMessageBox.information(
            self.ui,
            "Key Exported",
            f"Key '{key_name}' has been successfully exported to:\n{file_path}"
        )
 