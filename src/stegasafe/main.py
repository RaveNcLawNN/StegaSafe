import sys
from pathlib import Path

# Add src directory to Python path so imports work
# This allows "from stegasafe..." imports to work (like your colleagues use)
src_dir = Path(__file__).parent.parent
sys.path.insert(0, str(src_dir))

from PyQt6.QtWidgets import QApplication
from stegasafe.gui.controllers.main_window_controller import MainWindowController


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
