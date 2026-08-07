import base64
import json
import unittest

from vps.local_api import LocalAPIHandler
from vps.subscriptions import parse_subscription


class SubscriptionParserTest(unittest.TestCase):
    def test_parses_vless_reality_link(self):
        content = (
            "vless://11111111-1111-1111-1111-111111111111@vpn.example.com:443"
            "?encryption=none&security=reality&sni=www.example.com&pbk=public-key&sid=abcd"
            "&flow=xtls-rprx-vision&type=tcp#Tokyo"
        )

        result = parse_subscription(content)

        self.assertEqual(1, len(result.nodes))
        self.assertEqual(
            {
                "name": "Tokyo",
                "protocol": "Reality",
                "address": "vpn.example.com",
                "port": 443,
                "uuid": "11111111-1111-1111-1111-111111111111",
                "password": "",
                "sni": "www.example.com",
                "public_key": "public-key",
                "short_id": "abcd",
                "flow": "xtls-rprx-vision",
                "network": "tcp",
                "host": "",
                "path": "",
                "extra": "",
            },
            result.nodes[0],
        )
        self.assertEqual({"Reality": 1}, result.protocol_counts)

    def test_parses_base64_vmess_subscription(self):
        vmess = base64.b64encode(json.dumps({
            "ps": "VM Tokyo",
            "add": "vm.example.com",
            "port": "8443",
            "id": "22222222-2222-2222-2222-222222222222",
            "sni": "edge.example.com",
            "net": "ws",
            "host": "cdn.example.com",
            "path": "/ws",
        }).encode()).decode().rstrip("=")
        subscription = base64.b64encode(f"vmess://{vmess}\n".encode()).decode()

        result = parse_subscription(subscription)

        self.assertEqual(1, len(result.nodes))
        self.assertEqual("VMess", result.nodes[0]["protocol"])
        self.assertEqual("VM Tokyo", result.nodes[0]["name"])
        self.assertEqual("vm.example.com", result.nodes[0]["address"])
        self.assertEqual(8443, result.nodes[0]["port"])
        self.assertEqual("22222222-2222-2222-2222-222222222222", result.nodes[0]["uuid"])
        self.assertEqual("ws", result.nodes[0]["network"])
        self.assertEqual("cdn.example.com", result.nodes[0]["host"])
        self.assertEqual("/ws", result.nodes[0]["path"])

    def test_parses_supported_direct_link_protocols(self):
        ss_credentials = base64.urlsafe_b64encode(b"aes-256-gcm:ss-pass").decode().rstrip("=")
        ssr_password = base64.urlsafe_b64encode(b"ssr-pass").decode().rstrip("=")
        ssr_payload = base64.urlsafe_b64encode(
            f"ssr.example.com:8389:origin:aes-256-cfb:plain:{ssr_password}/?remarks=".encode()
        ).decode().rstrip("=")
        content = "\n".join((
            "trojan://trojan-pass@trojan.example.com:443?sni=tls.example.com#Trojan",
            "hy2://hy-pass@hy.example.com:8443?sni=hy-sni.example.com#HY2",
            "tuic://tuic-uuid:tuic-pass@tuic.example.com:443?sni=tuic-sni.example.com#TUIC",
            "naive+https://naive-user:naive-pass@naive.example.com:443?sni=naive-sni.example.com#Naive",
            f"ss://{ss_credentials}@ss.example.com:8388#SS",
            f"ssr://{ssr_payload}",
            "anytls://any-pass@any.example.com:443?sni=any-sni.example.com#AnyTLS",
        ))

        result = parse_subscription(content)

        self.assertEqual(
            ["Trojan", "Hysteria2", "TUIC", "Naive", "SS", "AnyTLS"],
            [node["protocol"] for node in result.nodes],
        )
        self.assertEqual("trojan-pass", result.nodes[0]["password"])
        self.assertEqual("hy-pass", result.nodes[1]["password"])
        self.assertEqual("tuic-uuid", result.nodes[2]["uuid"])
        self.assertEqual("tuic-pass", result.nodes[2]["password"])
        self.assertEqual("naive-user", result.nodes[3]["uuid"])
        self.assertEqual("aes-256-gcm", result.nodes[4]["uuid"])
        self.assertEqual("ss-pass", result.nodes[4]["password"])
        self.assertEqual("any-pass", result.nodes[5]["password"])
        self.assertEqual(1, result.debug["rejected"])

    def test_every_accepted_protocol_has_a_plain_subscription_export(self):
        vmess = base64.b64encode(json.dumps({
            "ps": "VMess",
            "add": "vmess.example.com",
            "port": "443",
            "id": "22222222-2222-2222-2222-222222222222",
        }).encode()).decode().rstrip("=")
        ss_credentials = base64.urlsafe_b64encode(b"aes-256-gcm:ss-pass").decode().rstrip("=")
        content = "\n".join((
            f"vmess://{vmess}",
            "vless://11111111-1111-1111-1111-111111111111@vless.example.com:443#VLESS",
            "vless://11111111-1111-1111-1111-111111111111@reality.example.com:443?security=reality&pbk=key#Reality",
            "trojan://trojan-pass@trojan.example.com:443#Trojan",
            "hy2://hy-pass@hy.example.com:8443#HY2",
            "tuic://tuic-uuid:tuic-pass@tuic.example.com:443#TUIC",
            "naive+https://naive-user:naive-pass@naive.example.com:443#Naive",
            f"ss://{ss_credentials}@ss.example.com:8388#SS",
            "anytls://any-pass@any.example.com:443#AnyTLS",
        ))

        result = parse_subscription(content)

        self.assertEqual(9, len(result.nodes))
        for node in result.nodes:
            with self.subTest(protocol=node["protocol"]):
                self.assertTrue(LocalAPIHandler._subscription_link(node))


if __name__ == "__main__":
    unittest.main()
