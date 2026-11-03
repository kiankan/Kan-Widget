import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QScrollArea

from kan_widget import KanWindow, MetricCard


class WindowSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_main_window_constructs_all_pages(self):
        window = KanWindow()
        try:
            self.assertEqual(window.pages.count(), 4)
            self.assertIsInstance(window.pages.widget(0), QScrollArea)
            self.assertEqual(len(window.nav_buttons), 4)
            self.assertEqual(window.page_title.text(), "داشبورد")
        finally:
            window.close()
            self.app.processEvents()

    def test_metric_card_has_theme_object_name(self):
        card = MetricCard("CPU", "◉", "5%", "test")
        self.assertEqual(card.objectName(), "metricCard")
        card.deleteLater()
        self.app.processEvents()


if __name__ == "__main__":
    unittest.main()
