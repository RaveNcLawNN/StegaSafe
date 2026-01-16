from PyQt6.QtWidgets import QMessageBox

from src.stegasafe.core.crypto.keygen import SymmetricKeyGen, AsymmetricKeyGen, KeySerializer
from stegasafe.utils.decorators import handle_ui_errors
from stegasafe.utils.exceptions import VaultError


class KeyGenController:
    def __init__(self, ui, key_vault_controller, on_keys_changed=None):
        self.ui = ui
        self.kv = key_vault_controller
        self.on_keys_changed = on_keys_changed

        self._populate_algorithm_boxes()
        self._wire_events()

    def _populate_algorithm_boxes(self):
        self.ui.cbSymmKeyAlgSelect.clear()
        self.ui.cbSymmKeyAlgSelect.addItems(["AES-128", "AES-192", "AES-256"])

        self.ui.cbKeypairAlgSelect.clear()
        self.ui.cbKeypairAlgSelect.addItems(["RSA-2048", "RSA-3072", "RSA-4096", "X25519", "Ed25519"])

    def _wire_events(self):
        self.ui.btnGenSymmKey.clicked.connect(self._generate_symmetric)
        self.ui.btnKeypairGen.clicked.connect(self._generate_keypair)

    def _require_unlocked_vault(self):
        if self.kv.vault_password is None:
            raise VaultError("Vault is locked. Please unlock the Key Vault first.")

    def _require_name(self, name: str, label: str):
        if not name.strip():
            raise ValueError(f"{label} is required.")

    @handle_ui_errors
    def _generate_symmetric(self, *args):
        self._require_unlocked_vault()

        name = self.ui.leSymmKeyName.text()
        self._require_name(name, "Key Name")

        alg = self.ui.cbSymmKeyAlgSelect.currentText()  # e.g. AES-256
        bits = int(alg.split("-")[1])

        key_bytes = SymmetricKeyGen.generate_aes_key(bits)

        self.kv.vault.add_key(
            name=name.strip(),
            kind="symmetric",
            algorithm="AES",
            material=key_bytes,
            password=self.kv.vault_password,
            role=None,
            bits=bits,
        )

        self.ui.leSymmKeyName.clear()
        QMessageBox.information(self.ui, "Key created", f"Stored symmetric key: {name}")

        self.kv.refresh_keys()
        if self.on_keys_changed:
            self.on_keys_changed()

    @handle_ui_errors
    def _generate_keypair(self, *args):
        self._require_unlocked_vault()

        name = self.ui.leKeypairName.text()
        self._require_name(name, "Keypair Name")

        selection = self.ui.cbKeypairAlgSelect.currentText()

        if selection.startswith("RSA-"):
            bits = int(selection.split("-")[1])
            priv = AsymmetricKeyGen.generate_rsa_key(bits)
            pub = priv.public_key()
            algorithm = "RSA"

            priv_pem = KeySerializer.private_key_to_pem(priv, password=None)
            pub_pem = KeySerializer.public_key_to_pem(pub)

        elif selection.upper() == "X25519":
            priv = AsymmetricKeyGen.generate_ecc_key("X25519")
            pub = priv.public_key()
            algorithm = "X25519"
            bits = None

            priv_pem = KeySerializer.private_key_to_pem(priv, password=None)
            pub_pem = KeySerializer.public_key_to_pem(pub)

        elif selection.upper() == "ED25519":
            priv = AsymmetricKeyGen.generate_ecc_key("ED25519")
            pub = priv.public_key()
            algorithm = "Ed25519"
            bits = None

            priv_pem = KeySerializer.private_key_to_pem(priv, password=None)
            pub_pem = KeySerializer.public_key_to_pem(pub)

        else:
            raise ValueError("Unsupported keypair algorithm selection.")

        # Store BOTH entries: private + public
        self.kv.vault.add_key(
            name=f"{name.strip()} (private)",
            kind="asymmetric",
            algorithm=algorithm,
            material=priv_pem,
            password=self.kv.vault_password,
            role="private",
            bits=bits,
        )
        self.kv.vault.add_key(
            name=f"{name.strip()} (public)",
            kind="asymmetric",
            algorithm=algorithm,
            material=pub_pem,
            password=self.kv.vault_password,
            role="public",
            bits=bits,
        )

        self.ui.leKeypairName.clear()
        QMessageBox.information(self.ui, "Keypair created", f"Stored keypair: {name}")

        self.kv.refresh_keys()
        if self.on_keys_changed:
            self.on_keys_changed()
