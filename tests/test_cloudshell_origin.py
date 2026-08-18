import json
import tempfile
import unittest
from pathlib import Path

from vps import cloudshell_origin


class CloudShellOriginTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.secrets = root / "secrets"
        self.data = root / "data"
        self.runtime = root / "runtime"
        self.secrets.mkdir()
        self.data.mkdir()
        (self.secrets / "cf-tunnel-creds.json").write_text(
            json.dumps({
                "AccountTag": "acct",
                "TunnelID": "11111111-2222-3333-4444-555555555555",
                "TunnelSecret": "secret",
                "Endpoint": "",
            }),
            encoding="utf-8",
        )
        (self.secrets / "uuid").write_text("e799e3d5-6f8b-46cd-bb68-6dd38a20f2d0\n", encoding="utf-8")
        (self.secrets / "cf-hostname").write_text("gcs.example.com\n", encoding="utf-8")
        (self.secrets / "sub-path").write_text("/sub-secret\n", encoding="utf-8")
        (self.secrets / "sub-front.yaml").write_text(
            '  - name: "Front·a.example"\n'
            "    type: vless\n"
            "    server: a.example\n"
            "    port: 443\n",
            encoding="utf-8",
        )
        (self.secrets / "res-domains.txt").write_text(
            "saas.example\nother.example 保底\n",
            encoding="utf-8",
        )
        (self.data / "internal_proxy.json").write_text(
            json.dumps({"username": "kui-gateway", "password": "internal-pass"}),
            encoding="utf-8",
        )
        cloudshell_origin.SECRETS_DIR = self.secrets
        cloudshell_origin.DATA_DIR = self.data
        cloudshell_origin.RUNTIME_DIR = self.runtime

    def tearDown(self):
        self.temp.cleanup()

    def test_runtime_inputs_read_docker_secrets_without_leaking_credentials(self):
        inputs = cloudshell_origin.load_runtime_inputs()
        self.assertEqual("gcs.example.com", inputs["hostname"])
        self.assertEqual("/sub-secret", inputs["sub_path"])
        self.assertEqual("kui-gateway", inputs["socks_user"])
        self.assertNotIn("TunnelSecret", json.dumps(inputs))

    def test_write_runtime_configs_maps_slots_to_xray_and_cloudflared_paths(self):
        inputs = cloudshell_origin.load_runtime_inputs()
        cloudshell_origin.write_runtime_configs(34, inputs)

        xray = json.loads((self.runtime / "xray.json").read_text(encoding="utf-8"))
        self.assertEqual(35, len(xray["inbounds"]))
        by_tag = {inbound["tag"]: inbound for inbound in xray["inbounds"]}
        self.assertEqual("/vless", by_tag["vless-base"]["streamSettings"]["wsSettings"]["path"])
        self.assertEqual(38090, by_tag["res-01"]["port"])
        self.assertEqual("/res-34", by_tag["res-34"]["streamSettings"]["wsSettings"]["path"])
        socks = {outbound["tag"]: outbound for outbound in xray["outbounds"] if outbound["tag"].startswith("socks-")}
        self.assertEqual(34, len(socks))
        self.assertEqual(7920, socks["socks-res-01"]["settings"]["servers"][0]["port"])
        self.assertEqual(7953, socks["socks-res-34"]["settings"]["servers"][0]["port"])
        self.assertEqual("internal-pass", socks["socks-res-01"]["settings"]["servers"][0]["users"][0]["pass"])
        routing = {rule["inboundTag"][0]: rule["outboundTag"] for rule in xray["routing"]["rules"]}
        self.assertEqual("direct", routing["vless-base"])
        self.assertEqual("socks-res-01", routing["res-01"])

        cloudflared = json.loads((self.runtime / "cloudflared.yml").read_text(encoding="utf-8"))
        self.assertEqual(0o644, (self.runtime / "cloudflared.yml").stat().st_mode & 0o777)
        self.assertEqual(inputs["tunnel_id"], cloudflared["tunnel"])
        routes = cloudflared["ingress"]
        self.assertEqual(r"^/vless$", routes[0]["path"])
        self.assertEqual(r"^/res-01$", routes[1]["path"])
        self.assertEqual("^/sub-secret$", routes[-2]["path"])
        self.assertEqual("http_status:404", routes[-1]["service"])
        self.assertEqual("http://kui-cloudshell-origin:38080", routes[0]["service"])
        self.assertEqual("http://kui-cloudshell-origin:38123", routes[-3]["service"])

    def test_subscription_keeps_legacy_groups_without_country_split(self):
        inputs = cloudshell_origin.load_runtime_inputs()
        exits = [
            {
                "id": "exit-01",
                "state": "ready",
                "egress_ip": "203.0.113.30",
                "detected_country": "JP",
                "egress_type": "residential",
                "check_result": {"residential": {"raw": {"isp": {"org": "Sony Network Communications"}}}},
            },
            {
                "id": "exit-02",
                "state": "ready",
                "egress_ip": "198.51.100.7",
                "detected_country": "FR",
                "egress_type": "datacenter",
                "check_result": {"residential": {"raw": {"isp": {"org": "OVH SAS"}}}},
            },
        ]
        body = cloudshell_origin.build_subscription_yaml(exits, inputs, cloudshell_origin.res_domains())

        self.assertIn('"Front·a.example"', body)
        self.assertIn("JP住宅·SonyNURO·exit-01", body)
        self.assertIn("JP住宅·SonyNURO·exit-01·保底", body)
        self.assertIn("FR机房·OVH·exit-02", body)
        self.assertIn('  - name: "🚀 节点选择"', body)
        self.assertIn('  - name: "⚡ 自动选择"', body)
        self.assertIn('  - name: "🏠 住宅自动"', body)
        self.assertIn('  - name: "🧠 Claude"', body)
        self.assertIn('  - name: "🤖 ChatGPT"', body)
        self.assertIn('  - name: "🔵 Google·Gemini"', body)
        self.assertIn("  - MATCH,🌐 其他流量", body)
        for forbidden in ("🇯🇵 JP", "🇰🇷 KR", "🇨🇦 CA", "直连节点", "链式节点", "admin-vps-住宅"):
            self.assertNotIn(forbidden, body)
        self.assertEqual(body.count("uuid: \"e799e3d5-6f8b-46cd-bb68-6dd38a20f2d0\""), 4)


if __name__ == "__main__":
    unittest.main()
