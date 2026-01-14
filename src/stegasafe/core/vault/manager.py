import base64
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from src.stegasafe.utils import read_bytes, write_bytes
from .protection import encrypt_json_bytes, decrypt_json_bytes


class KeyVault:
    """
    A very simple key vault:
    - Stores keys + metadata in a Python dict (self._data)
    - Saves/loads that dict as JSON
    - Encrypts the entire JSON with a master password (AES-GCM via protection.py)
    - Writes a single vault file to disk
    """
    def __init__(self, vault_path: str):
        # Path to the encrypted vault file on disk, e.g. "~/.stegasafe/vault.dat"
        self.vault_path = vault_path

        # In-memory representation of the vault.
        # "material_b64" stores key bytes encoded as base64 (because JSON can't store raw bytes).
        self._data = {"version": 1, "keys": []}

        # Simple safety flag: you must unlock() before listing/adding keys.
        self._unlocked = False

    def create_new(self, password: str) -> None:
        """Create a new empty vault file encrypted with the given password."""
        self._data = {"version": 1, "keys": []}
        self._unlocked = True
        self._save(password)

    def unlock(self, password: str) -> bool:
        """
        Load vault from disk and decrypt it using the password.
        If the vault file doesn't exist yet, automatically creates a new empty vault.
        If the vault version is unsupported, automatically resets to a new vault.
        If the password is wrong or the file is corrupt, decrypt_json_bytes raises ValueError.
        
        Returns:
            True if vault was auto-reset (old version), False otherwise
        """
        # If vault file doesn't exist, create a new empty one automatically.
        if not Path(self.vault_path).exists():
            self.create_new(password)
            return False

        # Try to load and decrypt the existing vault.
        try:
            blob = read_bytes(self.vault_path)
            plaintext = decrypt_json_bytes(blob, password)
            self._data = json.loads(plaintext.decode("utf-8"))
            self._unlocked = True
            return False  # Normal unlock, no reset
        except ValueError as e:
            error_msg = str(e)
            # If it's a version mismatch, automatically reset the vault
            if "Unsupported vault version" in error_msg or "Vault file is too small" in error_msg:
                # Delete the old vault file and create a new one
                try:
                    Path(self.vault_path).unlink()  # Delete old vault
                except Exception:
                    pass  # Ignore if deletion fails
                # Create a fresh vault with the same password
                self.create_new(password)
                return True  # Indicate that vault was reset
            else:
                # For other errors (wrong password, etc.), re-raise as-is
                raise

    def lock(self) -> None:
        """Lock the vault (prevents list/add/get until unlock() is called again)."""
        self._unlocked = False

    def list_keys(self, kind: str = None, role: str = None):
        """
        Return a list of key metadata for the UI (NO key material included).

        Filters:
        - kind: "symmetric" or "asymmetric"
        - role: "public" or "private" (usually only for asymmetric)
        """
        self._require_unlocked()
        keys = self._data["keys"]
        if kind is not None:
            keys = [k for k in keys if k.get("kind") == kind]
        if role is not None:
            keys = [k for k in keys if k.get("role") == role]
        # return metadata only (no key bytes)
        return [
            {kk: vv for kk, vv in k.items() if kk != "material_b64"}
            for k in keys
        ]

    def add_key(self, name: str, kind: str, algorithm: str, material: bytes, password: str, role: str = None, bits: int = None) -> str:
        """
        Add a key to the vault and save it immediately.

        - name: human-readable (shown in UI)
        - kind: "symmetric" / "asymmetric"
        - role: optional "public" / "private" (for asymmetric)
        - material: raw key bytes
        Returns the new key ID (UUID string).
        """
        self._require_unlocked()
        key_id = str(uuid.uuid4())
        entry = {
            "id": key_id,
            "name": name,
            "kind": kind,              # "symmetric" / "asymmetric"
            "algorithm": algorithm,    # "AES" / "RSA" / ...
            "role": role,              # "public" / "private" (optional)
            "bits": bits,              # optional
            "material_b64": base64.b64encode(material).decode("ascii"),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._data["keys"].append(entry)
        self._save(password)
        return key_id

    def get_key_material(self, key_id: str) -> bytes:
        """Return the raw key bytes for a given key ID (used by crypto code, not for UI display)."""
        self._require_unlocked()
        entry = self._find(key_id)
        return base64.b64decode(entry["material_b64"])

    def rename_key(self, key_id: str, new_name: str, password: str) -> None:
        """Rename a key and save the vault."""
        self._require_unlocked()
        entry = self._find(key_id)
        entry["name"] = new_name
        self._save(password)

    def delete_key(self, key_id: str, password: str) -> None:
        """Delete a key by ID and save the vault."""
        self._require_unlocked()
        self._data["keys"] = [k for k in self._data["keys"] if k["id"] != key_id]
        self._save(password)

    def _save(self, password: str) -> None:
        """
        Serialize self._data to JSON, encrypt it, and write it to disk.

        Important: ensure the parent directory exists (first run).
        """
        # Make sure "~/.stegasafe/" exists before writing the vault file.
        Path(self.vault_path).parent.mkdir(parents=True, exist_ok=True)

        plaintext = json.dumps(self._data, indent=2).encode("utf-8")
        blob = encrypt_json_bytes(plaintext, password)
        write_bytes(self.vault_path, blob)

    def _find(self, key_id: str):
        """Find a key entry dict by its ID."""
        for k in self._data["keys"]:
            if k["id"] == key_id:
                return k
        raise KeyError("Key not found")

    def _require_unlocked(self):
        """Internal guard to prevent using the vault before unlocking."""
        if not self._unlocked:
            raise RuntimeError("Vault is locked. Call unlock() first.")