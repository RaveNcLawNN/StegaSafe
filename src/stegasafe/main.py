import sys
from PyQt6.QtWidgets import QApplication
from gui.controllers.main_window_controller import MainWindowController


def main():
    app = QApplication(sys.argv)
    window = MainWindowController()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
