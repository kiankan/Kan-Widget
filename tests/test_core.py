import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from kan_widget import (
    decode_subscription,
    fetch_subscription_text,
    format_bytes,
    load_settings,
    parse_subscription,
    parse_uri,
    transport_from_query,
)


class ParserTests(unittest.TestCase):
    def test_vless_reality_websocket_and_alpn(self):
        link = (
            "vless://11111111-2222-3333-4444-555555555555@edge.example.com:443"
            "?encryption=none&security=reality&sni=cdn.example.com&fp=chrome"
            "&pbk=public-key&sid=0123&type=ws&host=cdn.example.com"
            "&path=%2Fsocket&alpn=h2%2Chttp%2F1.1#edge"
        )
        node = parse_uri(link)
        outbound = node["outbound"]
        self.assertEqual(node["name"], "edge")
        self.assertEqual(outbound["type"], "vless")
        self.assertEqual(outbound["tls"]["reality"]["short_id"], "0123")
        self.assertEqual(outbound["tls"]["alpn"], ["h2", "http/1.1"])
        self.assertEqual(outbound["transport"]["type"], "ws")
        self.assertEqual(outbound["transport"]["path"], "/socket")

    def test_vmess_base64_uri(self):
        config = {
            "add": "vmess.example.com",
            "port": "443",
            "id": "11111111-2222-3333-4444-555555555555",
            "aid": "0",
            "net": "ws",
            "tls": "tls",
            "host": "cdn.example.com",
            "path": "/vmess",
            "ps": "VMess test",
        }
        payload = base64.urlsafe_b64encode(json.dumps(config).encode()).decode().rstrip("=")
        node = parse_uri(f"vmess://{payload}")
        self.assertEqual(node["name"], "VMess test")
        self.assertEqual(node["outbound"]["transport"]["type"], "ws")
        self.assertTrue(node["outbound"]["tls"]["enabled"])

    def test_shadowsocks_base64_userinfo_and_plugin(self):
        credentials = base64.urlsafe_b64encode(
            b"chacha20-ietf-poly1305:secret-password"
        ).decode().rstrip("=")
        link = (
            f"ss://{credentials}@ss.example.com:8388"
            "?plugin=obfs-local%3Bobfs%3Dhttp#ss-node"
        )
        node = parse_uri(link)
        self.assertEqual(node["name"], "ss-node")
        self.assertEqual(node["outbound"]["method"], "chacha20-ietf-poly1305")
        self.assertEqual(node["outbound"]["password"], "secret-password")
        self.assertEqual(node["outbound"]["plugin"], "obfs-local")
        self.assertEqual(node["outbound"]["plugin_opts"], "obfs=http")

    def test_base64_subscription(self):
        plain = (
            "vless://11111111-2222-3333-4444-555555555555@one.example.com:443"
            "?security=tls&type=tcp#one"
        )
        encoded = base64.b64encode(plain.encode()).decode()
        self.assertIn("vless://", decode_subscription(encoded))
        nodes = parse_subscription(encoded)
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["name"], "one")

    def test_duplicate_servers_are_removed_even_if_names_differ(self):
        endpoint = "vless://11111111-2222-3333-4444-555555555555@one.example.com:443?security=tls"
        nodes = parse_subscription(endpoint + "#first\n" + endpoint + "#second")
        self.assertEqual(len(nodes), 1)

    def test_unsupported_transport_is_not_silently_downgraded(self):
        with self.assertRaises(ValueError):
            parse_uri(
                "vless://11111111-2222-3333-4444-555555555555@one.example.com:443"
                "?type=xhttp"
            )

    def test_unsupported_tcp_header_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_uri(
                "vless://11111111-2222-3333-4444-555555555555@one.example.com:443"
                "?type=tcp&headerType=http"
            )

    def test_invalid_subscription_url_is_rejected_before_network_access(self):
        with self.assertRaises(ValueError):
            fetch_subscription_text("file:///C:/Windows/win.ini")

    def test_format_bytes(self):
        self.assertEqual(format_bytes(0), "0.0 B/s")
        self.assertEqual(format_bytes(1024), "1.0 KB/s")

    def test_malformed_saved_entries_are_ignored(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            app_dir = Path(temp_dir)
            settings_file = app_dir / "settings.json"
            settings_file.write_text(
                json.dumps({
                    "apps": [None, {"name": "Editor", "path": "C:/Editor.exe"}, "bad-entry"],
                    "nodes": [
                        {"name": "valid", "outbound": {"type": "vless", "server": "example.com", "server_port": 443}},
                        {"name": "invalid", "outbound": "not-an-object"},
                        123,
                    ],
                    "tasks": [None, {"text": "Do work", "done": True}, {"text": 5}],
                    "proxy_snapshot": "invalid",
                }),
                encoding="utf-8",
            )
            with patch("kan_widget.APP_DIR", app_dir), patch("kan_widget.SETTINGS_FILE", settings_file):
                settings = load_settings()

        self.assertEqual(len(settings["apps"]), 1)
        self.assertEqual(settings["apps"][0]["name"], "Editor")
        self.assertEqual(len(settings["nodes"]), 1)
        self.assertEqual(settings["nodes"][0]["name"], "valid")
        self.assertEqual(settings["tasks"], [{"text": "Do work", "done": True}])
        self.assertIsNone(settings["proxy_snapshot"])


if __name__ == "__main__":
    unittest.main()
