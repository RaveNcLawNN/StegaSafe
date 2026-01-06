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

    def _unlock_vault(self):
        password = self.ui.leVaultPassword.text()
        if not password:
            self._error("Missing password", "Please enter a vault password.")
            return

        try:
            self.vault.unlock(password)
            self.vault_password = password

            self.ui.leVaultPassword.clear()
            self._show_unlocked_ui()
            self.refresh_keys()

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
        # Top line
        self.ui.leSelectedKey.setText(meta.get("name", ""))

        # self.ui.lblKeyName.setText(meta.get("name", "-"))
        self.ui.lblKeyType.setText(meta.get("kind", "-"))
        self.ui.lblKeyAlgorithms.setText(meta.get("algorithm", "-"))
        self.ui.lblKeyVisibility.setText(meta.get("role", "symmetric/none") if meta.get("role") else "n/a")
        self.ui.lblKeyID.setText(meta.get("id", "-"))
        self.ui.lblKeyLength.setText(str(meta.get("bits", "-")))
        self.ui.lblKeySize.setText("-")  # keep placeholder unless you define what “size” means

    def _clear_details(self):
        self.ui.leSelectedKey.clear()

        self.ui.lblKeyName.setText("-")
        self.ui.lblKeyType.setText("-")
        self.ui.lblKeyAlgorithms.setText("-")
        self.ui.lblKeyVisibility.setText("-")
        self.ui.lblKeyID.setText("-")
        self.ui.lblKeyLength.setText("-")
        self.ui.lblKeySize.setText("-")
