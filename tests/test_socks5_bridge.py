import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vps.slot_config import BASE_PROXY_PORT, MAX_SLOT_COUNT
from vps.socks5_bridge import build_socks5_bridge_config, run_bridge


class Socks5BridgeConfigTest(unittest.TestCase):
    def test_publishes_all_managed_slots_with_management_auth(self):
        config = build_socks5_bridge_config(
            slot_count=3,
            socks_host="kui-local-multi-exit",
            socks_base_port=BASE_PROXY_PORT,
            auto_port=1080,
            public_user="admin",
            public_password="secret",
            internal_user="kui-gateway",
            internal_password="internal-secret",
        )

        inbound_ports = sorted(item["listen_port"] for item in config["inbounds"])
        self.assertEqual([1080, 7920, 7921, 7922], inbound_ports)
        for inbound in config["inbounds"]:
            self.assertEqual(
                [{"username": "admin", "password": "secret"}],
                inbound["users"],
            )

        slot_outbounds = [item for item in config["outbounds"] if item["type"] == "socks"]
        self.assertEqual(
            [7920, 7921, 7922],
            [item["server_port"] for item in slot_outbounds],
        )
        self.assertTrue(all(item["username"] == "kui-gateway" for item in slot_outbounds))
        self.assertTrue(all(item["password"] == "internal-secret" for item in slot_outbounds))
        self.assertEqual(
            {"inbound": "exit-01", "outbound": "exit-01"},
            config["route"]["rules"][0],
        )
        self.assertEqual("auto", config["route"]["final"])

    def test_rejects_invalid_slot_count(self):
        with self.assertRaisesRegex(ValueError, "KUI_SLOT_COUNT"):
            build_socks5_bridge_config(
                slot_count=MAX_SLOT_COUNT + 1,
                socks_host="kui-local-multi-exit",
                socks_base_port=BASE_PROXY_PORT,
                auto_port=1080,
                public_user="admin",
                public_password="secret",
                internal_user="kui-gateway",
                internal_password="internal-secret",
            )


class Socks5BridgeRunTest(unittest.TestCase):
    def test_writes_checked_config_then_execs_sing_box(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            credentials = workspace / "internal_proxy.json"
            credentials.write_text(
                json.dumps({"username": "kui-gateway", "password": "internal-secret"}),
                encoding="utf-8",
            )
            config_file = workspace / "config.json"
            with patch.dict(
                os.environ,
                {
                    "KUI_SLOT_COUNT": "2",
                    "KUI_MANAGEMENT_USER": "admin",
                    "KUI_MANAGEMENT_PASSWORD": "secret",
                    "KUI_INTERNAL_PROXY_WORKSPACE": str(workspace),
                    "KUI_SOCKS5_BRIDGE_CONFIG_FILE": str(config_file),
                    "KUI_SING_BOX_BIN": "sing-box",
                    "KUI_SOCKS5_AUTO_PORT": "1080",
                    "KUI_REALITY_SOCKS_HOST": "kui-local-multi-exit",
                    "KUI_REALITY_SOCKS_BASE_PORT": "7920",
                },
                clear=False,
            ):
                with patch("vps.socks5_bridge.shutil.which", return_value="/usr/local/bin/sing-box"):
                    with patch("vps.socks5_bridge.check_sing_box_config") as check:
                        with patch("vps.socks5_bridge.exec_sing_box") as exec_box:
                            result = run_bridge(do_exec=True)

            self.assertTrue(config_file.is_file())
            self.assertEqual(0o600, config_file.stat().st_mode & 0o777)
            payload = json.loads(config_file.read_text(encoding="utf-8"))
            self.assertEqual(3, len(payload["inbounds"]))
            check.assert_called_once()
            exec_box.assert_called_once()
            self.assertEqual(str(config_file), result["config_file"])


if __name__ == "__main__":
    unittest.main()
