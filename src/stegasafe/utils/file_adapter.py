"""Simple file adapter for reading and writing files."""


def read_bytes(path):
    """Read a file and return its contents as bytes."""
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        raise Exception("File does not exist")
    except PermissionError:
        raise Exception("No permission to read file")


def write_bytes(path, data):
    """Write bytes to a file."""
    try:
        with open(path, "wb") as f:
            f.write(data)
    except PermissionError:
        raise Exception("No permission to write file")
    except Exception as e:
        raise Exception(f"Error writing file: {str(e)}")
