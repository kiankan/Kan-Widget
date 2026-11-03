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

    def test_pro_dashboard_contains_live_chart_storage_and_vpn_widget(self):
        window = KanWindow()
        try:
            self.assertEqual(window.pages.count(), 4)
            self.assertIsNotNone(window.usage_chart)
            self.assertIsNotNone(window.storage_progress)
            self.assertIsNotNone(window.dashboard_node_combo)
            self.assertIsNotNone(window.dashboard_connect_button)
            self.assertIsNotNone(window.dashboard_disconnect_button)
            self.assertIsNotNone(window.quick_apps)
            self.assertIsNotNone(window.apps_grid)
            self.assertEqual(window.usage_chart.cpu_values[-1], 0.0)
            window.usage_chart.add_sample(37.0, 62.0)
            self.assertEqual(window.usage_chart.cpu_values[-1], 37.0)
            self.assertEqual(window.usage_chart.ram_values[-1], 62.0)
        finally:
            window.close()
            self.app.processEvents()

    def test_dashboard_and_vpn_server_selectors_stay_in_sync(self):
        window = KanWindow()
        try:
            window.settings["nodes"] = [
                {"name": "Test Germany", "outbound": {"type": "vless", "server": "de.example.test", "server_port": 443}},
                {"name": "Test Finland", "outbound": {"type": "trojan", "server": "fi.example.test", "server_port": 443}},
            ]
            window.settings["selected_node"] = "Test Germany"
            window._load_nodes()
            self.assertEqual(window.node_combo.count(), 2)
            self.assertEqual(window.dashboard_node_combo.count(), 2)
            window.dashboard_node_combo.setCurrentIndex(1)
            self.assertEqual(window.node_combo.currentIndex(), 1)
            self.assertEqual(window.settings["selected_node"], "Test Finland")
        finally:
            window.close()
            self.app.processEvents()


if __name__ == "__main__":
    unittest.main()
