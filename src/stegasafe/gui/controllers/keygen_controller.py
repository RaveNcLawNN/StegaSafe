from PyQt6.QtWidgets import QMessageBox

from src.stegasafe.core.crypto.keygen import SymmetricKeyGen, AsymmetricKeyGen, KeySerializer


class KeyGenController:
    def __init__(self, ui, key_vault_controller, on_keys_changed=None):
        """
        Constructor: Initializes the generation logic and binds it to the UI.
        - Injection: Receives the KeyVaultController to allow direct saving
          of generated keys into the encrypted vault.
        - Observer: Stores the callback to notify the MainController when
          new keys are created.
        """
        self.ui = ui
        self.kv = key_vault_controller
        self.on_keys_changed = on_keys_changed

        self._populate_algorithm_boxes()
        self._wire_events()

    def _populate_algorithm_boxes(self):
        """
        Defines available cryptographic standards.
        - Sets explicit AES bit-lengths for symmetric encryption.
        - Provides RSA and Elliptic Curve (X25519/Ed25519) options for asymmetric pairs.
        """
        self.ui.cbSymmKeyAlgSelect.clear()
        self.ui.cbSymmKeyAlgSelect.addItems(["AES-128", "AES-192", "AES-256"])

        self.ui.cbKeypairAlgSelect.clear()
        self.ui.cbKeypairAlgSelect.addItems(["RSA-2048", "RSA-3072", "RSA-4096", "X25519", "Ed25519"])

    def _wire_events(self):
        """Connects UI buttons to generation methods."""
        self.ui.btnGenSymmKey.clicked.connect(self._generate_symmetric)
        self.ui.btnKeypairGen.clicked.connect(self._generate_keypair)

    def _require_unlocked_vault(self):
        """
        Ensures the Vault is ready for new keys.
        - Requirement: Vault must be unlocked to provide the master password
          needed to encrypt the newly generated key material.
        """
        if self.kv.vault_password is None:
            raise RuntimeError("Vault is locked. Please unlock the Key Vault first.")

    def _require_name(self, name: str, label: str):
        """Ensures user-provided labels are not empty."""
        if not name.strip():
            raise ValueError(f"{label} is required.")

    def _generate_symmetric(self):
        """
        Symmetric Key Generation:
        - Logic: Uses SymmetricKeyGen to create random bytes for AES.
        - Persistence: Adds the key to the vault immediately.
        - UI Update: Clears input and triggers the app-wide refresh callback.
        """
        try:
            self._require_unlocked_vault()

            name = self.ui.leSymmKeyName.text()
            self._require_name(name, "Key Name")

            alg = self.ui.cbSymmKeyAlgSelect.currentText()
            bits = int(alg.split("-")[1])

            # Generate raw key material
            key_bytes = SymmetricKeyGen.generate_aes_key(bits)

            # Secure the key in the vault
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

            # Notify system to refresh dropdowns in other tabs
            self.kv.refresh_keys()
            if self.on_keys_changed:
                self.on_keys_changed()

        except Exception as e:
            QMessageBox.critical(self.ui, "Key generation failed", str(e))

    def _generate_keypair(self):
        """
        Asymmetric Key Generation:
        - Logic: Handles RSA (bit-based) and ECC (curve-based) generation.
        - Serialization: Converts keys to PEM format using KeySerializer.
        - Storage: Generates and stores two distinct entries (Public and Private).
        """
        try:
            self._require_unlocked_vault()

            name = self.ui.leKeypairName.text()
            self._require_name(name, "Keypair Name")

            selection = self.ui.cbKeypairAlgSelect.currentText()

            # Handle RSA generation
            if selection.startswith("RSA-"):
                bits = int(selection.split("-")[1])
                priv = AsymmetricKeyGen.generate_rsa_key(bits)
                pub = priv.public_key()
                algorithm = "RSA"

                priv_pem = KeySerializer.private_key_to_pem(priv, password=None)
                pub_pem = KeySerializer.public_key_to_pem(pub)

            # Handle ECC generation (X25519/Ed25519)
            elif selection.upper() in ["X25519", "ED25519"]:
                algorithm = selection
                priv = AsymmetricKeyGen.generate_ecc_key(algorithm)
                pub = priv.public_key()
                bits = None

                priv_pem = KeySerializer.private_key_to_pem(priv, password=None)
                pub_pem = KeySerializer.public_key_to_pem(pub)

            else:
                raise ValueError("Unsupported keypair algorithm selection.")

            # Store Private Component
            self.kv.vault.add_key(
                name=f"{name.strip()} (private)",
                kind="asymmetric",
                algorithm=algorithm,
                material=priv_pem,
                password=self.kv.vault_password,
                role="private",
                bits=bits,
            )
            # Store Public Component
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

            # Notify system
            self.kv.refresh_keys()
            if self.on_keys_changed:
                self.on_keys_changed()

        except Exception as e:
            QMessageBox.critical(self.ui, "Keypair generation failed", str(e))