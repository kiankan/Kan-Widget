import base64
import json
import unittest

from kan_widget import (
    decode_subscription,
    fetch_subscription_text,
    format_bytes,
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


if __name__ == "__main__":
    unittest.main()
