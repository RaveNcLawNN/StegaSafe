import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from stegasafe.utils.exceptions import VaultError

# Small note on how vault encryption works (beginner-friendly):
# - The user enters a master password
# - We generate a random salt and derive a strong 32-byte key via PBKDF2
# - We encrypt the vault JSON using AES-GCM (confidentiality + tamper detection)
#
# Vault file layout (bytes on disk):
#   MAGIC (b"STEGAVAULT") | VERSION (1 byte) | SALT (16) | NONCE (12) | CIPHERTEXT+TAG (variable)
# The salt/nonce are NOT secret; they are stored so we can decrypt later.

# Constant header so we can recognize "this is a StegaSafe vault file".
MAGIC = b"STEGAVAULT"
# File format version (lets you change format later without breaking old vaults).
VERSION = b"\x01"

def derive_key(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    """
    Turn a user password into a 32-byte AES key using PBKDF2-HMAC-SHA256.

    - salt: random bytes stored in the vault file (prevents rainbow-table attacks)
    - iterations: slows down brute-force guessing
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_json_bytes(plaintext: bytes, password: str) -> bytes:
    """
    Encrypt vault JSON bytes with a key derived from the password.
    Returns the complete vault file bytes (header + salt + nonce + ciphertext).
    """
    salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    # AES-GCM needs a nonce/IV. 12 bytes is the standard size.
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # file format: MAGIC | version | salt | nonce | ciphertext(+tag)
    return MAGIC + VERSION + salt + nonce + ciphertext


def decrypt_json_bytes(blob: bytes, password: str) -> bytes:
    """
    Decrypt vault file bytes using the provided password.
    Raises VaultError on wrong password, corrupted file, or wrong format.
    """
    if not blob.startswith(MAGIC):
        # Specific error for invalid file types
        raise VaultError("The selected file is not a valid StegaSafe vault file.")

    # Check if file is too small (old format or corrupted)
    if len(blob) < 38:  # MAGIC(9) + VERSION(1) + SALT(16) + NONCE(12) = minimum 38 bytes
        raise VaultError("The vault file appears to be corrupted or incomplete. Please check the file and try again.")

    # MAGIC is 9 bytes long, then 1 byte version.
    version = blob[9:10]
    if version != VERSION:
        # Show what version was found for debugging
        found_version = version.hex() if version else "empty"
        expected_version = VERSION.hex()
        raise VaultError(
            f"Unsupported vault version (Found: {found_version}, Expected: {expected_version}). "
            "Please ensure you are using the correct version of StegaSafe."
        )

    salt = blob[10:26]
    nonce = blob[26:38]
    ciphertext = blob[38:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise VaultError("Vault unlock failed. Please check your master password and try again.")