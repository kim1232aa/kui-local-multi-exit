import base64
import json
import unittest

from vps.local_api import LocalAPIHandler
from vps.subscriptions import generate_singbox_config, parse_subscription


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
                "extra": "{\"security\":\"reality\"}",
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


    def test_parses_authenticated_socks5_link(self):
        result = parse_subscription("socks5://proxy-user:proxy-pass@socks.example.com:1080#SOCKS")

        self.assertEqual(1, len(result.nodes))
        node = result.nodes[0]
        self.assertEqual("Socks5", node["protocol"])
        self.assertEqual("proxy-pass", node["password"])
        self.assertEqual("proxy-user", json.loads(node["extra"])["username"])

    def test_singbox_output_covers_reality_vless_socks_and_valid_references(self):
        nodes = [
            {
                "name": "Reality",
                "protocol": "Reality",
                "address": "reality.example.com",
                "port": 443,
                "uuid": "11111111-1111-1111-1111-111111111111",
                "sni": "www.example.com",
                "public_key": "reality-public-key",
                "short_id": "abcd",
                "flow": "xtls-rprx-vision",
                "network": "tcp",
            },
            {
                "name": "VLESS WS",
                "protocol": "VLESS",
                "address": "vless.example.com",
                "port": 443,
                "uuid": "22222222-2222-2222-2222-222222222222",
                "sni": "cdn.example.com",
                "network": "ws",
                "host": "cdn.example.com",
                "path": "/proxy",
                "extra": json.dumps({"security": "tls", "fingerprint": "chrome"}),
            },
            {
                "name": "SOCKS5",
                "protocol": "socks5",
                "address": "socks.example.com",
                "port": 1080,
                "username": "socks-user",
                "password": "socks-pass",
            },
            {
                # A duplicate display name must still become a distinct tag.
                "name": "SOCKS5",
                "protocol": "Socks5",
                "address": "socks2.example.com",
                "port": 1081,
            },
            {
                # SSR is retained by URI exports, but must not poison sing-box JSON.
                "name": "SSR",
                "protocol": "SSR",
                "address": "ssr.example.com",
                "port": 8388,
            },
        ]

        config = json.loads(generate_singbox_config(nodes))
        outbounds = config["outbounds"]
        tags = [outbound["tag"] for outbound in outbounds]
        self.assertEqual(len(tags), len(set(tags)))
        self.assertNotIn("dns", {outbound["type"] for outbound in outbounds})

        known_tags = set(tags)
        for outbound in outbounds:
            if outbound["type"] in {"selector", "urltest"}:
                self.assertTrue(set(outbound["outbounds"]) <= known_tags)

        reality = next(outbound for outbound in outbounds if outbound["tag"] == "Reality")
        self.assertEqual("vless", reality["type"])
        self.assertEqual("reality-public-key", reality["tls"]["reality"]["public_key"])
        self.assertEqual("abcd", reality["tls"]["reality"]["short_id"])
        vless = next(outbound for outbound in outbounds if outbound["tag"] == "VLESS WS")
        self.assertEqual({"type": "ws", "path": "/proxy", "headers": {"Host": "cdn.example.com"}}, vless["transport"])
        socks = next(outbound for outbound in outbounds if outbound["tag"] == "SOCKS5")
        self.assertEqual("socks", socks["type"])
        self.assertEqual("socks-user", socks["username"])
        self.assertNotIn("SSR", tags)


    def test_parses_vless_tls_and_reality_aliases(self):
        content = "\n".join((
            "vless://11111111-1111-1111-1111-111111111111@tls.example.com:8443"
            "?security=tls&servername=edge.example.com&type=grpc&serviceName=edge-grpc"
            "&fp=firefox&allow_insecure=1#TLS",
            "vless://22222222-2222-2222-2222-222222222222@reality.example.com:443"
            "?security=REALITY&public_key=reality-key&short_id=abcd&sni=www.example.com#Reality Alias",
        ))

        result = parse_subscription(content)

        self.assertEqual(["VLESS", "Reality"], [node["protocol"] for node in result.nodes])
        tls_node, reality_node = result.nodes
        self.assertEqual("edge.example.com", tls_node["sni"])
        self.assertEqual("grpc", tls_node["network"])
        self.assertEqual(
            {
                "security": "tls",
                "fingerprint": "firefox",
                "service_name": "edge-grpc",
                "insecure": True,
            },
            json.loads(tls_node["extra"]),
        )
        self.assertEqual("reality-key", reality_node["public_key"])
        self.assertEqual("abcd", reality_node["short_id"])
        self.assertEqual("www.example.com", reality_node["sni"])

    def test_singbox_output_covers_local_socks_and_supported_thirdparty_protocols(self):
        nodes = [
            {
                "name": "Local SOCKS5",
                "protocol": "socks",
                "address": "127.0.0.1",
                "port": 7920,
                "username": "local-user",
                "password": "local-pass",
            },
            {
                "name": "Reality aliases",
                "protocol": "VLESS",
                "address": "reality.example.com",
                "port": 443,
                "uuid": "11111111-1111-1111-1111-111111111111",
                "servername": "www.example.com",
                "tls": True,
                "reality-opts": {"public-key": "reality-public-key", "short-id": "abcd"},
            },
            {
                "name": "VMess",
                "protocol": "VMess",
                "address": "vmess.example.com",
                "port": 443,
                "uuid": "22222222-2222-2222-2222-222222222222",
            },
            {
                "name": "Trojan",
                "protocol": "Trojan",
                "address": "trojan.example.com",
                "port": 443,
                "private_key": "trojan-secret",
            },
            {
                "name": "Hysteria2",
                "protocol": "Hysteria2",
                "address": "hy.example.com",
                "port": 8443,
                "private_key": "hy-secret",
                "network": "udp",
            },
            {
                "name": "TUIC",
                "protocol": "TUIC",
                "address": "tuic.example.com",
                "port": 443,
                "uuid": "33333333-3333-3333-3333-333333333333",
                "private_key": "tuic-secret",
            },
            {
                "name": "Naive",
                "protocol": "Naive",
                "address": "naive.example.com",
                "port": 443,
                "uuid": "naive-user",
                "private_key": "naive-secret",
                "sni": "edge.example.com",
            },
            {
                "name": "SS",
                "protocol": "SS",
                "address": "ss.example.com",
                "port": 8388,
                "uuid": "aes-256-gcm",
                "password": "ss-secret",
            },
            {
                "name": "AnyTLS",
                "protocol": "AnyTLS",
                "address": "anytls.example.com",
                "port": 443,
                "private_key": "anytls-secret",
            },
        ]

        config = json.loads(generate_singbox_config(nodes))
        by_tag = {outbound["tag"]: outbound for outbound in config["outbounds"]}

        self.assertEqual("socks", by_tag["Local SOCKS5"]["type"])
        self.assertEqual("127.0.0.1", by_tag["Local SOCKS5"]["server"])
        self.assertEqual(7920, by_tag["Local SOCKS5"]["server_port"])
        self.assertEqual("local-user", by_tag["Local SOCKS5"]["username"])
        self.assertEqual("local-pass", by_tag["Local SOCKS5"]["password"])

        reality = by_tag["Reality aliases"]
        self.assertEqual("vless", reality["type"])
        self.assertEqual("reality-public-key", reality["tls"]["reality"]["public_key"])
        self.assertEqual("abcd", reality["tls"]["reality"]["short_id"])
        self.assertNotIn("flow", reality)

        expected_types = {
            "VMess": "vmess",
            "Trojan": "trojan",
            "Hysteria2": "hysteria2",
            "TUIC": "tuic",
            "Naive": "naive",
            "SS": "shadowsocks",
            "AnyTLS": "anytls",
        }
        self.assertEqual(expected_types, {tag: by_tag[tag]["type"] for tag in expected_types})
        self.assertEqual("trojan-secret", by_tag["Trojan"]["password"])
        self.assertEqual("hy-secret", by_tag["Hysteria2"]["password"])
        self.assertEqual("udp", by_tag["Hysteria2"]["network"])
        self.assertEqual("tuic-secret", by_tag["TUIC"]["password"])
        self.assertEqual("naive-secret", by_tag["Naive"]["password"])
        self.assertEqual(
            {"enabled": True, "server_name": "edge.example.com"},
            by_tag["Naive"]["tls"],
        )
        self.assertEqual("aes-256-gcm", by_tag["SS"]["method"])
        self.assertEqual("anytls-secret", by_tag["AnyTLS"]["password"])


if __name__ == "__main__":
    unittest.main()
