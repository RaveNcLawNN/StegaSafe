class StegaSafeError(Exception):
    """
    Base class for all application errors. Provides a default title for UI dialogs.
    """
    def __init__(self, message, title="Operation Failed"):
        super().__init__(message)
        self.title = title
        self.message = message

# --- General System & UI Errors ---

class ValidationError(StegaSafeError):
    """Raised general input validation (empty fields, invalid paths)."""
    def __init__(self, message):
        super().__init__(message, title="Validation Error")

class ProcessingError(StegaSafeError):
    """Raised for utility failures like decompression or format conversion."""
    def __init__(self, message):
        super().__init__(message, title="Data Processing Error")

# --- Security & Storage Errors ---

class VaultError(StegaSafeError):
    """Raised for vault locking, unlocking, or master password issues."""
    def __init__(self, message):
        super().__init__(message, title="Vault Error")

class KeyGenerationError(StegaSafeError):
    """Raised for failures during key creation (unsupported sizes/algorithms)."""
    def __init__(self, message):
        super().__init__(message, title="Key Generation Failed")

# --- Cryptographic Feature Errors ---

class CryptographyError(StegaSafeError):
    """Raised for AES encryption/decryption or padding failures."""
    def __init__(self, message):
        super().__init__(message, title="Cryptography Error")

class SignatureError(StegaSafeError):
    """Raised for digital signing or verification failures."""
    def __init__(self, message):
        super().__init__(message, title="Signature Error")

class IntegrityError(StegaSafeError):
    """Raised for hashing failures or integrity mismatches."""
    def __init__(self, message):
        super().__init__(message, title="Integrity Check Failed")

# --- Steganography Feature Errors ---

class SteganographyError(StegaSafeError):
    """Raised for LSB or Metadata embedding and extraction errors."""
    def __init__(self, message):
        super().__init__(message, title="Steganography Error")

class CapacityError(SteganographyError):
    """Raised for when payload exceeds image capacity."""
    def __init__(self, message):
        # We still use the "Steganography Error" title for UI consistency
        super().__init__(message, title="Capacity Exceeded")