from PyQt6.QtWidgets import QMessageBox, QTreeWidgetItem
from PyQt6.QtCore import Qt

from src.stegasafe.core.vault.manager import KeyVault


class KeyVaultController:
    def __init__(self, ui, vault_path: str, on_keys_changed=None):
        self.ui = ui
        self.vault = KeyVault(vault_path)
        self.vault_password = None
        self.on_keys_changed = on_keys_changed

        self.ui.swKeyVault.setCurrentWidget(self.ui.pgePassword)

        DEMO_DEFAULT_PASSWORD = True
        if DEMO_DEFAULT_PASSWORD:
            self.ui.leVaultPassword.setText("123")

        self._wire_events()

        self.ui.twKeys.itemSelectionChanged.connect(self._on_key_selected)
        self._keys_cache = {}

    def _wire_events(self):
        self.ui.btnUnlockVault.clicked.connect(self._unlock_vault)
        self.ui.btnDelete.clicked.connect(self._delete_key)
        self.ui.btnRename.clicked.connect(self._rename_key)

    def _unlock_vault(self):
        password = self.ui.leVaultPassword.text()
        if not password:
            self._error("Missing password", "Please enter a vault password.")
            return

        try:
            was_reset = self.vault.unlock(password)
            self.vault_password = password

            self.ui.leVaultPassword.clear()
            self._show_unlocked_ui()
            self.refresh_keys()
            
            # Show info message if vault was auto-reset
            if was_reset:
                QMessageBox.information(
                    self.ui,
                    "Vault Reset",
                    "Your vault file was from an older version and has been automatically reset.\n\n"
                    "A new empty vault has been created. You can now add keys again."
                )

        except Exception as e:
            self._error("Vault unlock failed", str(e))

    def _show_unlocked_ui(self):
        # switch stacked widget page
        self.ui.swKeyVault.setCurrentWidget(self.ui.pgeUnlocked)

    # ---------- key listing ----------
    def refresh_keys(self):
        try:
            keys = self.vault.list_keys()
            self._keys_cache = {k["id"]: k for k in keys}
            self._populate_tree(keys)
            self._clear_details()

        except Exception as e:
            self._error("Vault error", str(e))

    def _populate_tree(self, keys):
        tree = self.ui.twKeys
        tree.clear()

        for k in keys:
            label = k["name"]

            item = QTreeWidgetItem([label])
            item.setData(0, Qt.ItemDataRole.UserRole, k["id"])
            tree.addTopLevelItem(item)

    # ---------- helpers ----------
    def _error(self, title, message):
        QMessageBox.critical(self.ui, title, message)

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
        # Top line - make it editable so user can rename
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
    
    # ---------- key actions ----------
    def _get_selected_key_id(self):
        """Get the ID of the currently selected key, or None if none selected."""
        items = self.ui.twKeys.selectedItems()
        if not items:
            return None
        return items[0].data(0, Qt.ItemDataRole.UserRole)
    
    def _delete_key(self):
        """Delete the currently selected key."""
        key_id = self._get_selected_key_id()
        if not key_id:
            self._error("No key selected", "Please select a key to delete.")
            return
        
        # Confirm deletion
        reply = QMessageBox.question(
            self.ui,
            "Confirm Delete",
            f"Are you sure you want to delete this key?\n\nThis action cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        try:
            if not self.vault_password:
                raise RuntimeError("Vault is locked.")
            
            self.vault.delete_key(key_id, self.vault_password)
            self.refresh_keys()
            
            if self.on_keys_changed:
                self.on_keys_changed()
            
            QMessageBox.information(self.ui, "Key Deleted", "Key has been deleted successfully.")
        
        except Exception as e:
            self._error("Delete Failed", str(e))
    
    def _rename_key(self):
        """Rename the currently selected key."""
        key_id = self._get_selected_key_id()
        if not key_id:
            self._error("No key selected", "Please select a key to rename.")
            return
        
        # Get new name from the text field
        new_name = self.ui.leSelectedKey.text().strip()
        if not new_name:
            self._error("Invalid name", "Please enter a new name for the key.")
            return
        
        try:
            if not self.vault_password:
                raise RuntimeError("Vault is locked.")
            
            self.vault.rename_key(key_id, new_name, self.vault_password)
            self.refresh_keys()
            
            if self.on_keys_changed:
                self.on_keys_changed()
            
            QMessageBox.information(self.ui, "Key Renamed", "Key has been renamed successfully.")
        
        except Exception as e:
            self._error("Rename Failed", str(e))
 