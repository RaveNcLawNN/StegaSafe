from PyQt6.QtWidgets import QMainWindow
from PyQt6.uic import loadUi
from pathlib import Path

# Importing sub-controllers
from stegasafe.gui.controllers.cryptography_controller import CryptoTabController
from stegasafe.gui.controllers.key_vault_controller import KeyVaultController
from stegasafe.gui.controllers.keygen_controller import KeyGenController
from stegasafe.gui.controllers.hash_controller import HashTabController
from stegasafe.gui.controllers.vault_key_provider import VaultKeyProvider
from stegasafe.gui.controllers.steganography_controller import SteganographyTabController
from stegasafe.gui.controllers.signatures_controller import SignatureTabController


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

        # WICHTIG: Event-Listener für Tab-Wechsel hinzufügen
        # Sorgt dafür, dass Listen aktualisiert werden, sobald der User den Tab anklickt
        self.tabWidget.currentChanged.connect(self._on_tab_changed)

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
        """Callback: Wird gefeuert, wenn ein Key generiert oder importiert wurde."""
        if hasattr(self, "crypto_controller"):
            self.crypto_controller.refresh_keys()

        if hasattr(self, "signature_controller"):
            self.signature_controller.refresh_keys()

    def _on_tab_changed(self, index):
        """
        Handler für Tab-Wechsel.
        Zwingt die Controller dazu, ihre UI zu aktualisieren, wenn der User den Tab öffnet.
        """
        current_widget = self.tabWidget.widget(index)

        # 1. Wenn User auf "Cryptography" klickt -> Keys neu laden
        # (Behebt das Problem, dass neue Keys nicht sofort sichtbar waren)
        if current_widget == getattr(self, 'tabCryptography', None):
            if hasattr(self, 'crypto_controller'):
                self.crypto_controller.refresh_keys()

        # 2. Wenn User auf "Signatures" klickt -> Keys neu laden
        elif current_widget == getattr(self, 'tabSignatures', None):
            if hasattr(self, 'signature_controller'):
                self.signature_controller.refresh_keys()

        # 3. Wenn User auf "Key Vault" klickt -> Statusanzeige aktualisieren
        elif current_widget == getattr(self, 'tabKeyVault', None):
            if hasattr(self, 'key_vault_controller'):
                self.key_vault_controller.on_tab_selected()