from PyQt6.QtWidgets import QMainWindow
from PyQt6.uic import loadUi
from pathlib import Path

from src.stegasafe.gui.controllers.cryptography_controller import CryptoTabController
from src.stegasafe.gui.controllers.mock_key_provider import MockKeyProvider

class MainWindowController(QMainWindow):
    def __init__(self):
        super().__init__()

        ui_path = Path(__file__).parent.parent / "main_window.ui"
        loadUi(ui_path, self)

        self.key_provider = MockKeyProvider()

        self._init_tab_controllers()

    def _init_tab_controllers(self):
        # Cryptography tab controller (stub for now)
        self.crypto_controller = CryptoTabController(
            ui=self,
            key_provider=self.key_provider
        )
