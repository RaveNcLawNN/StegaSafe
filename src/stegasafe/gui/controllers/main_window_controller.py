from PyQt6.QtWidgets import QMainWindow
from PyQt6.uic import loadUi
from pathlib import Path

# Importing sub-controllers
from src.stegasafe.gui.controllers.cryptography_controller import CryptoTabController
from src.stegasafe.gui.controllers.key_vault_controller import KeyVaultController
from src.stegasafe.gui.controllers.keygen_controller import KeyGenController
from src.stegasafe.gui.controllers.hash_controller import HashTabController
from src.stegasafe.gui.controllers.vault_key_provider import VaultKeyProvider
from src.stegasafe.gui.controllers.steganography_controller import SteganographyTabController
from src.stegasafe.gui.controllers.signatures_controller import SignatureTabController


class MainWindowController(QMainWindow):
    def __init__(self):
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
        self.key_provider = VaultKeyProvider(self.key_vault_controller)

        # Finalize initialization of consumer tabs (Crypto, Stegano, etc.)
        self._init_tab_controllers()

    def _init_tab_controllers(self):
        self.crypto_controller = CryptoTabController(
            ui=self,
            key_provider=self.key_provider
        )
        
        self.hash_controller = HashTabController(ui=self)

        self.stego_controller = SteganographyTabController(ui=self)

        self.signature_controller = SignatureTabController(
            ui=self,
            key_provider=self.key_provider
        )

    def _keys_changed(self):
        if hasattr(self, "crypto_controller"):
            self.crypto_controller.refresh_keys()

        if hasattr(self, "signature_controller"):
            self.signature_controller.refresh_keys()