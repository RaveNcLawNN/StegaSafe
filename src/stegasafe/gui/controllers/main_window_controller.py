from PyQt6.QtWidgets import QMainWindow
from PyQt6.uic import loadUi
from pathlib import Path

# Importing sub-controllers
from src.stegasafe.gui.controllers.cryptography_controller import CryptoTabController
from src.stegasafe.gui.controllers.key_vault_controller import KeyVaultController
from src.stegasafe.gui.controllers.keygen_controller import KeyGenController
from src.stegasafe.gui.controllers.mock_key_provider import MockKeyProvider


class MainWindowController(QMainWindow):
    def __init__(self):
        """
        Orchestrates UI loading and controller dependencies.
        - Loads 'main_window.ui' to build the interface dynamically.
        - Initializes KeyVaultController with a local path (~/.stegasafe/vault.dat).
        - Connects KeyGenController to the Vault
        - Establishes a shared KeyProvider to bridge the Vault and Feature tabs.
        """
        super().__init__()

        # Dynamic UI loading via PyQt6
        ui_path = Path(__file__).parent.parent / "main_window.ui"
        loadUi(ui_path, self)

        # Initialize core identity/storage management
        self.key_vault_controller = KeyVaultController(
            ui=self,
            vault_path=str(Path.home() / ".stegasafe" / "vault.dat"),
            on_keys_changed=self._keys_changed
        )

        # Initialize key generation logic linked to the vault
        self.keygen_controller = KeyGenController(
            ui=self,
            key_vault_controller=self.key_vault_controller,
            on_keys_changed=self._keys_changed
        )

        # Shared interface for cryptographic modules to access key material
        self.key_provider = MockKeyProvider()

        # Finalize initialization of consumer tabs (Crypto, Stegano, etc.)
        self._init_tab_controllers()

    def _init_tab_controllers(self):
        """
        Sub-module Setup: Hooks specialized logic into the main UI.
        - Separated to ensure backend providers are fully ready before injection.
        - Injects key_provider into CryptoTabController to allow decryption/encryption.
        """
        self.crypto_controller = CryptoTabController(
            ui=self,
            key_provider=self.key_provider
        )

    def _keys_changed(self):
        """
        Observer Callback: Synchronizes state across all application tabs.
        - Triggered by KeyGen or Vault controllers whenever the key list changes.
        - Forces the Cryptography tab to refresh its dropdowns/views immediately.
        """
        if hasattr(self, "crypto_controller"):
            self.crypto_controller.refresh_keys()