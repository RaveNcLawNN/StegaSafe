import functools
from PyQt6.QtWidgets import QMessageBox
from stegasafe.utils.exceptions import StegaSafeError


def handle_ui_errors(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            # Pass *args to handle PyQt6 signals
            return func(self, *args, **kwargs)

        except Exception as e:
            # 1. Check if it's one of the custom errors by looking for the 'title' attribute
            if hasattr(e, "title") and hasattr(e, "message"):
                QMessageBox.critical(self.ui, e.title, e.message)
                return

            # 2. Check for ValueError/input issues
            if isinstance(e, ValueError):
                QMessageBox.warning(self.ui, "Input Error", str(e))
                return

            # 3. Fallback for genuine System Errors
            QMessageBox.critical(self.ui, "System Error",
                                 f"An unexpected technical error occurred:\n\n{str(e)}")

    return wrapper