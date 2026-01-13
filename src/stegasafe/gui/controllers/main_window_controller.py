from PyQt6.QtWidgets import QMainWindow
from PyQt6.uic import loadUi
from pathlib import Path

from src.stegasafe.gui.controllers.cryptography_controller import CryptoTabController
from src.stegasafe.gui.controllers.key_vault_controller import KeyVaultController
from src.stegasafe.gui.controllers.keygen_controller import KeyGenController
from src.stegasafe.gui.controllers.hash_controller import HashTabController
from src.stegasafe.gui.controllers.mock_key_provider import MockKeyProvider
from src.stegasafe.gui.controllers.steganography_controller import SteganographyTabController


class MainWindowController(QMainWindow):
    def __init__(self):
        super().__init__()

        ui_path = Path(__file__).parent.parent / "main_window.ui"
        loadUi(ui_path, self)

        self.key_vault_controller = KeyVaultController(
            ui=self,
            vault_path=str(Path.home() / ".stegasafe" / "vault.dat"),
            on_keys_changed=self._keys_changed
        )

        self.keygen_controller = KeyGenController(
            ui=self,
            key_vault_controller=self.key_vault_controller,
            on_keys_changed=self._keys_changed
        )

        self.key_provider = MockKeyProvider()

        self._init_tab_controllers()

    def _init_tab_controllers(self):
        self.crypto_controller = CryptoTabController(
            ui=self,
            key_provider=self.key_provider
        )
        
        self.hash_controller = HashTabController(ui=self)

        self.stego_controller = SteganographyTabController(ui=self)

    def _keys_changed(self):
        if hasattr(self, "crypto_controller"):
            self.crypto_controller.refresh_keys()