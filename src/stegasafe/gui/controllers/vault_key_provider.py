from stegasafe.utils.exceptions import VaultError

class VaultKeyProvider:
    def __init__(self, key_vault_controller):
        # We store the controller because it holds the current vault_password
        self.kv_controller = key_vault_controller

    def list_keys(self, kind=None):
        """Returns the current list of key metadata from the vault."""
        return self.kv_controller.vault.list_keys(kind=kind)

    def get_key_material(self, key_id: str) -> bytes:
        """Retrieves actual decrypted secret bytes from the vault."""
        if not self.kv_controller.vault_password:
            raise VaultError("Vault is locked! Please unlock the Key Vault tab first.")

        return self.kv_controller.vault.get_key_material(key_id)
