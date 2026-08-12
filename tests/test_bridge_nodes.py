import base64
import json
import unittest
from unittest.mock import patch

from vps import bridge_nodes
from vps.bridge_nodes import (
    CHECK_TARGETS,
    check_node_with_singbox,
    check_proxy_url,
    load_bridge_nodes,
    parse_proxy_url,
    parse_subscription,
)


class BridgeNodeParseTest(unittest.TestCase):
    def test_parse_vless_ws_url(self):
        url = (
            "vless://fba8e89d-6b9f-471f-a766-db6e4c275af1@104.18.46.46:443"
            "?type=ws&security=tls&sni=jlsjp2.jswstlsweb.top&fp=edge"
            "&path=%2Fjsjc%2Fjp2&host=jlsjp2.jswstlsweb.top&encryption=none"
            "#%F0%9F%87%AF%F0%9F%87%B5%E6%97%A5%E6%9C%AC%E4%B8%9C%E4%BA%AC2"
        )
        node = parse_proxy_url(url)
        self.assertIsNotNone(node)
        self.assertEqual(node["type"], "vless")
        self.assertEqual(node["protocol"], "VLESS")
        self.assertEqual(node["server"], "104.18.46.46")
        self.assertEqual(node["address"], "104.18.46.46")
        self.assertEqual(node["port"], 443)
        self.assertEqual(node["uuid"], "fba8e89d-6b9f-471f-a766-db6e4c275af1")
        self.assertEqual(node["network"], "ws")
        self.assertTrue(node["tls"])
        self.assertEqual(node["servername"], "jlsjp2.jswstlsweb.top")
        self.assertEqual(node["client-fingerprint"], "edge")
        self.assertEqual(node["ws-opts"]["path"], "/jsjc/jp2")
        self.assertEqual(node["ws-opts"]["headers"]["Host"], "jlsjp2.jswstlsweb.top")

    def test_parse_hysteria2_url(self):
        url = (
            "hysteria2://c973a568-f457-4884-a483-2f2f661b0b92@153.121.38.245:8443"
            "?sni=fastcdn.hoyoverse.com&insecure=1#Hysteria2"
        )
        node = parse_proxy_url(url)
        self.assertIsNotNone(node)
        self.assertEqual(node["type"], "hysteria2")
        self.assertEqual(node["protocol"], "HYSTERIA2")
        self.assertEqual(node["server"], "153.121.38.245")
        self.assertEqual(node["address"], "153.121.38.245")
        self.assertEqual(node["port"], 8443)
        self.assertEqual(node["password"], "c973a568-f457-4884-a483-2f2f661b0b92")
        self.assertEqual(node["sni"], "fastcdn.hoyoverse.com")
        self.assertTrue(node["skip-cert-verify"])

    def test_parse_vmess_url(self):
        raw = {
            "v": "2",
            "ps": "test-vmess",
            "add": "1.2.3.4",
            "port": "443",
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "aid": "0",
            "scy": "auto",
            "net": "ws",
            "type": "none",
            "host": "example.com",
            "path": "/ws",
            "tls": "tls",
            "sni": "example.com",
        }
        payload = base64.b64encode(json.dumps(raw).encode()).decode()
        node = parse_proxy_url(f"vmess://{payload}")
        self.assertIsNotNone(node)
        self.assertEqual(node["type"], "vmess")
        self.assertEqual(node["protocol"], "VMESS")
        self.assertEqual(node["server"], "1.2.3.4")
        self.assertEqual(node["port"], 443)
        self.assertEqual(node["uuid"], "550e8400-e29b-41d4-a716-446655440000")

    def test_parse_trojan_url(self):
        url = "trojan://secret@1.2.3.4:443?sni=example.com#TrojanNode"
        node = parse_proxy_url(url)
        self.assertIsNotNone(node)
        self.assertEqual(node["type"], "trojan")
        self.assertEqual(node["protocol"], "TROJAN")
        self.assertEqual(node["password"], "secret")
        self.assertEqual(node["sni"], "example.com")

    def test_parse_ss_url(self):
        creds = base64.b64encode(b"aes-256-gcm:password").decode()
        url = f"ss://{creds}@1.2.3.4:8388#SSNode"
        node = parse_proxy_url(url)
        self.assertIsNotNone(node)
        self.assertEqual(node["type"], "ss")
        self.assertEqual(node["protocol"], "SS")
        self.assertEqual(node["cipher"], "aes-256-gcm")
        self.assertEqual(node["password"], "password")

    def test_parse_subscription_base64(self):
        url1 = "ss://" + base64.b64encode(b"aes-256-gcm:p1").decode() + "@1.1.1.1:1#A"
        url2 = "trojan://secret@2.2.2.2:443?sni=x#B"
        text = base64.b64encode(f"{url1}\n{url2}\n".encode()).decode()
        nodes = parse_subscription(text)
        self.assertEqual(len(nodes), 2)
        self.assertEqual(nodes[0]["name"], "A")
        self.assertEqual(nodes[1]["name"], "B")

    def test_parse_monosans_json_keeps_geo_and_drops_transparent_nodes(self):
        payload = json.dumps([
            {
                "protocol": "socks5",
                "host": "198.51.100.1",
                "port": 1080,
                "exit_ip": "198.51.100.1",
                "geolocation": {"country": {"iso_code": "TH"}},
            },
            {
                "protocol": "http",
                "host": "198.51.100.2",
                "port": 8080,
                "exit_ip": "203.0.113.2",
                "geolocation": {"country": {"iso_code": "VN"}},
            },
            {"protocol": "socks4", "host": "198.51.100.3", "port": 1080},
        ])

        nodes = parse_subscription(payload)

        self.assertEqual(1, len(nodes))
        self.assertEqual("SOCKS5", nodes[0]["protocol"])
        self.assertEqual("TH", nodes[0]["_country_hint"])
        self.assertEqual("198.51.100.1", nodes[0]["address"])


class BridgeNodeCheckTest(unittest.TestCase):
    def test_check_proxy_url_returns_empty_for_unsupported_protocol(self):
        self.assertEqual(check_proxy_url("vless://x@1.2.3.4:443#n"), [])

    @patch("vps.bridge_nodes.subprocess.run")
    def test_check_proxy_url_counts_2xx_as_ok(self, mock_run):
        class Result:
            stdout = "200"
        mock_run.return_value = Result()
        ok = check_proxy_url("http://1.2.3.4:8080")
        self.assertEqual(len(ok), len(CHECK_TARGETS))

    @patch("vps.bridge_nodes._sing_box_bin")
    @patch("vps.bridge_nodes.subprocess.Popen")
    def test_check_node_with_singbox_skips_when_binary_missing(self, mock_popen, mock_bin):
        mock_bin.return_value = None
        node = parse_proxy_url(
            "vless://fba8e89d-6b9f-471f-a766-db6e4c275af1@104.18.46.46:443"
            "?type=ws&security=tls&sni=x&path=/&host=x#n"
        )
        self.assertEqual(check_node_with_singbox(node), [])
        mock_popen.assert_not_called()


class BridgeNodeLoadTest(unittest.TestCase):
    @patch("vps.bridge_nodes.fetch_subscription")
    @patch("vps.bridge_nodes.check_node_with_singbox")
    def test_load_bridge_nodes_tests_subscription_nodes(self, mock_check, mock_fetch):
        mock_fetch.return_value = (
            "vless://uuid@1.2.3.4:443?type=ws&security=tls&sni=x&path=/&host=x#SubNode\n"
        )
        mock_check.return_value = CHECK_TARGETS[:2]
        nodes = load_bridge_nodes(
            subscription_urls=["https://example.com/sub"],
            test_reachability=True,
        )
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["name"], "SubNode")
        self.assertEqual(nodes[0].get("bridge_ok_sites"), CHECK_TARGETS[:2])

    def test_load_bridge_nodes_trusts_manual_nodes(self):
        url = "hysteria2://pass@1.2.3.4:8443?sni=x#ManualNode"
        nodes = load_bridge_nodes(manual_urls=[url], test_reachability=True)
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["name"], "ManualNode")

    def test_load_bridge_nodes_uses_cache(self):
        from vps.bridge_nodes import _bridge_cache

        _bridge_cache.clear()
        url = "hysteria2://pass@1.2.3.4:8443?sni=x#Cached"
        first = load_bridge_nodes(manual_urls=[url], test_reachability=False)
        second = load_bridge_nodes(manual_urls=[url], test_reachability=False)
        self.assertEqual(first, second)
        self.assertGreaterEqual(len(_bridge_cache), 1)

    @patch("vps.bridge_nodes.load_bridge_nodes")
    def test_start_background_refresh_starts_daemon_thread(self, mock_load):
        mock_load.return_value = []
        thread = bridge_nodes.start_background_refresh(
            interval=1,
            manual_urls=["hysteria2://p@1.2.3.4:8443#x"],
            subscription_urls=[],
        )
        self.assertTrue(thread.daemon)
        self.assertEqual(thread.name, "bridge-refresh")
        thread.join(timeout=0.5)
        mock_load.assert_called()


if __name__ == "__main__":
    unittest.main()
