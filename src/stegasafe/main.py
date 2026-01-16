import sys
from pathlib import Path

# Add project root to Python path so imports work
# This allows "from src.stegasafe..." imports to work
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from PyQt6.QtWidgets import QApplication
from src.stegasafe.gui.controllers.main_window_controller import MainWindowController


def main():
    app = QApplication(sys.argv)
    window = MainWindowController()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main = QApplication(sys.argv)
    try:
        window = MainWindowController()
        window.show()
        sys.exit(main.exec())
    except Exception as e:
        print(f"CRITICAL APP CRASH: {e}")
