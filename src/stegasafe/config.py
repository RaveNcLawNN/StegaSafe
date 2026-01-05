from pathlib import Path

# Where StegaSafe stores its local application data (key vault, etc.).
# We use a hidden folder inside the user's home directory so it is:
# - not inside the git repo
# - the same place every time on that machine/user account
APP_DIR = Path.home() / ".stegasafe"

# The encrypted vault file (contains keys + metadata, encrypted with a master password).
VAULT_PATH = APP_DIR / "vault.dat"