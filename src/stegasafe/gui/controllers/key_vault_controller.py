from PyQt6.QtWidgets import QMessageBox, QTreeWidgetItem
from PyQt6.QtCore import Qt

from stegasafe.core.vault.manager import KeyVault
from stegasafe.utils.decorators import handle_ui_errors


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

        if was_reset:
            QMessageBox.information(
                self.ui,
                "Vault Reset",
                f"{message}\n\nYou can now add keys to the new vault."
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
 