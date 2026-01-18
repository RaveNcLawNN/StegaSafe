import sys
import ctypes
from pathlib import Path

if sys.platform == "win32":
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
        "stegasafe.app"
    )

# Add src directory to Python path so imports work
src_dir = Path(__file__).parent.parent
sys.path.insert(0, str(src_dir))

from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtGui import QIcon
from stegasafe.gui.controllers.main_window_controller import MainWindowController


def main():
    app = QApplication(sys.argv)

    base_dir = Path(__file__).resolve().parent  # src/stegasafe
    css_path = base_dir / "gui" / "style.css"
    icon_path = base_dir / "gui" / "stegasafe_dino_transparent.png"

    # Application + taskbar icon
    icon = QIcon(str(icon_path))
    app.setWindowIcon(icon)

    # Load global stylesheet
    with open(css_path, "r", encoding="utf-8") as f:
        app.setStyleSheet(f.read())

    window = MainWindowController()
    window.setWindowIcon(icon)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        app = QApplication.instance() or QApplication(sys.argv)
        QMessageBox.critical(
            None,
            "Fatal Error",
            "An unexpected internal error occurred.\nPlease restart the application."
        )
        print(f"CRITICAL APP CRASH: {e}")
