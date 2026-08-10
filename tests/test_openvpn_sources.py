import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vps import openvpn_sources


PROFILE = """client
dev tun
proto tcp
remote 203.0.113.9 443
<ca>
CERT
</ca>
"""


class OpenVPNSourcesTest(unittest.TestCase):
    def test_manual_provider_imports_per_profile_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider = root / "proton" / "US"
            provider.mkdir(parents=True)
            profile = provider / "us-free.ovpn"
            profile.write_text(PROFILE, encoding="utf-8")
            profile.with_suffix(".json").write_text(
                json.dumps({"country": "US", "username": "account", "password": "secret", "source": "proton"}),
                encoding="utf-8",
            )

            nodes = openvpn_sources.load_manual_nodes(root)

        self.assertEqual(1, len(nodes))
        self.assertEqual("US", nodes[0]["country"])
        self.assertEqual("account", nodes[0]["username"])
        self.assertEqual("secret", nodes[0]["password"])
        self.assertEqual("proton", nodes[0]["source"])

    def test_vpnbook_imports_tcp_profiles_and_shared_credentials(self):
        page = (
            '<span>Germany Server</span>'
            '<script>self.__next_f.push([1,"{\\"servers\\":[{\\"id\\":\\"de20\\",'
            '\\"hostname\\":\\"de20.vpnbook.com\\",\\"countryCode\\":\\"DE\\"}]}" ])</script>'
            '<label>Password</label><code class="x">pass123</code>'
        )

        def fetch(url, timeout=20):
            if url == openvpn_sources.VPNBOOK_PAGE_URL:
                return page
            self.assertIn("hostname=de20.vpnbook.com", url)
            self.assertIn("protocol=tcp443", url)
            return PROFILE.replace("203.0.113.9", "198.51.100.20")

        with patch.object(openvpn_sources, "_fetch_text", side_effect=fetch):
            nodes = openvpn_sources.fetch_vpnbook_nodes()

        self.assertEqual(1, len(nodes))
        self.assertEqual("DE", nodes[0]["country"])
        self.assertEqual("vpnbook", nodes[0]["username"])
        self.assertEqual("pass123", nodes[0]["password"])
        self.assertEqual("vpnbook", nodes[0]["source"])

    def test_multi_source_aggregation_keeps_provider_report(self):
        vpngate_node = {
            "ip": "203.0.113.9", "country": "JP", "ping": 1, "score": 1,
            "config": "proto tcp\n", "harvested_at": 1.0,
        }
        vpnbook_node = {**vpngate_node, "ip": "198.51.100.20", "country": "DE", "source": "vpnbook"}
        with patch("vps.vpngate.fetch_nodes", return_value=[vpngate_node]), patch.object(
            openvpn_sources, "fetch_vpnbook_nodes", return_value=[vpnbook_node]
        ), patch.object(openvpn_sources, "load_manual_nodes", return_value=[]), patch.object(
            openvpn_sources, "fetch_publicvpnlist_catalog", return_value={"countries": {"DE": 4}}
        ):
            nodes, report = openvpn_sources.fetch_all_openvpn_nodes()

        self.assertEqual(2, len(nodes))
        self.assertEqual(1, report["providers"]["vpngate"]["count"])
        self.assertEqual(1, report["providers"]["vpnbook"]["count"])
        self.assertTrue(report["providers"]["publicvpnlist"]["metadata_only"])


if __name__ == "__main__":
    unittest.main()
