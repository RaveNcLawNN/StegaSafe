from PyQt6.QtWidgets import QMessageBox, QTreeWidgetItem
from PyQt6.QtCore import Qt

from src.stegasafe.core.vault.manager import KeyVault


class KeyVaultController:
    def __init__(self, ui, vault_path: str, on_keys_changed=None):
        """
        Constructor: Initializes the security gateway and local storage.
        - Logic: Establishes the KeyVault backend with a local file path.
        - UI State: Forces the StackedWidget to 'pgePassword' on startup,
          ensuring the app is 'Locked by Default' for security.
        - Observer: Stores the callback to notify the MainController of changes.
        """
        self.ui = ui
        self.vault = KeyVault(vault_path)
        self.vault_password = None
        self.on_keys_changed = on_keys_changed

        # UI initial state
        self.ui.swKeyVault.setCurrentWidget(self.ui.pgePassword)

        DEMO_DEFAULT_PASSWORD = True
        if DEMO_DEFAULT_PASSWORD:
            self.ui.leVaultPassword.setText("123")

        self._wire_events()
        self.ui.twKeys.itemSelectionChanged.connect(self._on_key_selected)
        self._keys_cache = {}

    def _wire_events(self):
        """Signal Mapping: Connects interactive UI elements to logic."""
        self.ui.btnUnlockVault.clicked.connect(self._unlock_vault)

    def _unlock_vault(self):
        """
        Authentication Logic: Attempts to decrypt the local vault file.
        - Validation: Ensures password field is not empty.
        - Security: Calls vault.unlock(). If it fails, an exception is caught.
        - Success: Switches the UI view, clears the password field from memory,
          and triggers a refresh of the key list.
        """
        password = self.ui.leVaultPassword.text()
        if not password:
            self._error("Missing password", "Please enter a vault password.")
            return

        try:
            # Attempt to decrypt the vault using the provided password
            self.vault.unlock(password)
            self.vault_password = password

            # Cleanup UI and transition to the Unlocked Management page
            self.ui.leVaultPassword.clear()
            self._show_unlocked_ui()
            self.refresh_keys()

            # Notify other controllers that keys are now accessible
            if self.on_keys_changed:
                self.on_keys_changed()

        except Exception as e:
            self._error("Vault unlock failed", str(e))

    def _show_unlocked_ui(self):
        """ransitions the stacked widget to the management view."""
        self.ui.swKeyVault.setCurrentWidget(self.ui.pgeUnlocked)

    def refresh_keys(self):
        """
        Synchronizes the UI tree with the actual vault contents.
        - Retrieves metadata for all stored keys.
        - Populates the tree widget and clears the detail sidebar.
        """
        try:
            keys = self.vault.list_keys()
            self._keys_cache = {k["id"]: k for k in keys}
            self._populate_tree(keys)
            self._clear_details()

        except Exception as e:
            self._error("Vault error", str(e))

    def _populate_tree(self, keys):
        """
        Maps key metadata to the QTreeWidget.
        - Stores the unique Key ID in the UserRole of the item to
          ensure secure and accurate selection handling.
        """
        tree = self.ui.twKeys
        tree.clear()

        for k in keys:
            label = k["name"]
            item = QTreeWidgetItem([label])
            # Associate the internal ID with the UI element for later retrieval
            item.setData(0, Qt.ItemDataRole.UserRole, k["id"])
            tree.addTopLevelItem(item)

    def _on_key_selected(self):
        """
        Displays metadata when a user clicks a key.
        - Retrieves the ID from the selected tree item.
        - Looks up the full metadata in the local _keys_cache.
        """
        items = self.ui.twKeys.selectedItems()
        if not items:
            self._clear_details()
            return

        key_id = items[0].data(0, Qt.ItemDataRole.UserRole)
        meta = self._keys_cache.get(key_id)
        if meta:
            self._show_details(meta)
        else:
            self._clear_details()

    def _show_details(self, meta: dict):
        """
        pdates UI labels with specific key properties.
        - Fulfills NFR3 by providing a clear overview of the selected asset.
        """
        self.ui.leSelectedKey.setText(meta.get("name", ""))
        self.ui.lblKeyType.setText(meta.get("kind", "-"))
        self.ui.lblKeyAlgorithms.setText(meta.get("algorithm", "-"))
        self.ui.lblKeyVisibility.setText(meta.get("role", "symmetric/none") if meta.get("role") else "n/a")
        self.ui.lblKeyID.setText(meta.get("id", "-"))
        self.ui.lblKeyLength.setText(str(meta.get("bits", "-")))
        self.ui.lblKeySize.setText("-")

    def _clear_details(self):
        """Clears all detail labels to a neutral state."""
        self.ui.leSelectedKey.clear()
        self.ui.lblKeyName.setText("-")
        self.ui.lblKeyType.setText("-")
        self.ui.lblKeyAlgorithms.setText("-")
        self.ui.lblKeyVisibility.setText("-")
        self.ui.lblKeyID.setText("-")
        self.ui.lblKeyLength.setText("-")
        self.ui.lblKeySize.setText("-")

    def _error(self, title, message):
        QMessageBox.critical(self.ui, title, message)