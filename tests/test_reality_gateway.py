import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from vps.reality_gateway import (
    build_public_nodes_manifest,
    build_sing_box_config,
    check_sing_box_config,
    generate_x25519_keypair,
    get_public_ip,
    load_or_create_identities,
    run_gateway,
)


class TestRealityGateway(unittest.TestCase):
    @patch("vps.reality_gateway.subprocess.run")
    @patch("vps.reality_gateway.shutil.which", return_value="/usr/local/bin/sing-box")
    def test_generate_x25519_keypair(self, _mock_which, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "PrivateKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
                "PublicKey: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n"
            ),
            stderr="",
        )

        private_key, public_key = generate_x25519_keypair()

        self.assertEqual("A" * 43, private_key)
        self.assertEqual("B" * 43, public_key)
        mock_run.assert_called_once_with(
            ["/usr/local/bin/sing-box", "generate", "reality-keypair"],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_get_public_ip_from_env(self):
        with patch.dict(os.environ, {"KUI_REALITY_PUBLIC_HOST": "1.2.3.4"}):
            self.assertEqual("1.2.3.4", get_public_ip())

        with patch.dict(os.environ, {"KUI_PUBLIC_HOST": "5.6.7.8", "KUI_REALITY_PUBLIC_HOST": ""}):
            self.assertEqual("5.6.7.8", get_public_ip())

    def test_get_public_ip_fetch_failure_requires_explicit_host(self):
        with patch.dict(os.environ, {"KUI_REALITY_PUBLIC_HOST": "", "KUI_PUBLIC_HOST": ""}):
            with patch("urllib.request.urlopen", side_effect=Exception("network error")):
                with self.assertRaisesRegex(RuntimeError, "set KUI_PUBLIC_HOST"):
                    get_public_ip()

    def test_get_public_ip_fetch_success(self):
        with patch.dict(os.environ, {"KUI_REALITY_PUBLIC_HOST": "", "KUI_PUBLIC_HOST": ""}):
            mock_resp = MagicMock()
            mock_resp.read.return_value = b"203.0.113.19\n"
            mock_resp.__enter__.return_value = mock_resp
            with patch("urllib.request.urlopen", return_value=mock_resp):
                self.assertEqual("203.0.113.19", get_public_ip())

    @patch("vps.reality_gateway.generate_x25519_keypair", return_value=("A" * 43, "B" * 43))
    def test_load_or_create_identities_uses_shared_key_and_preserves_extra_records(self, mock_generate):
        with tempfile.TemporaryDirectory() as tmpdir:
            identities_file = Path(tmpdir) / "identities.json"
            identities1 = load_or_create_identities(identities_file, count=2)

            self.assertEqual(["exit-01", "exit-02"], list(identities1))
            self.assertEqual(1, mock_generate.call_count)
            self.assertEqual(identities1["exit-01"]["private_key"], identities1["exit-02"]["private_key"])
            self.assertEqual(identities1["exit-01"]["short_id"], identities1["exit-02"]["short_id"])
            self.assertEqual("0o600", oct(identities_file.stat().st_mode & 0o777))

            identities2 = load_or_create_identities(identities_file, count=4)
            self.assertEqual([f"exit-{index:02d}" for index in range(1, 5)], list(identities2))
            self.assertEqual(1, mock_generate.call_count)
            self.assertEqual(identities1["exit-01"]["uuid"], identities2["exit-01"]["uuid"])
            stored = json.loads(identities_file.read_text(encoding="utf-8"))["nodes"]
            self.assertEqual({"exit-01", "exit-02", "exit-03", "exit-04"}, set(stored))

    def test_build_sing_box_config_uses_one_shared_reality_inbound(self):
        identities = {
            f"exit-{i:02d}": {
                "slot_id": f"exit-{i:02d}",
                "uuid": f"00000000-0000-0000-0000-{i:012d}",
                "private_key": "privkeybase64testsample123456789012345678",
                "public_key": "pubkeybase64testsample123456789012345678",
                "short_id": "01234567",
            }
            for i in range(1, 4)
        }

        config = build_sing_box_config(
            identities,
            socks_host="kui-local-multi-exit",
            socks_base_port=7920,
            reality_port=8443,
            sni="dl.google.com",
            proxy_user="vpn",
            proxy_password="vpn",
        )

        self.assertEqual("info", config["log"]["level"])
        self.assertEqual(1, len(config["inbounds"]))
        self.assertEqual(3, len(config["outbounds"]))
        self.assertEqual(3, len(config["route"]["rules"]))
        inbound = config["inbounds"][0]
        self.assertEqual("vless", inbound["type"])
        self.assertEqual("xtls-reality", inbound["tag"])
        self.assertEqual(8443, inbound["listen_port"])
        self.assertEqual(["exit-01", "exit-02", "exit-03"], [user["name"] for user in inbound["users"]])
        self.assertEqual("privkeybase64testsample123456789012345678", inbound["tls"]["reality"]["private_key"])

        self.assertEqual(7920, config["outbounds"][0]["server_port"])
        self.assertEqual(7922, config["outbounds"][2]["server_port"])
        rule = config["route"]["rules"][1]
        self.assertEqual(["xtls-reality"], rule["inbound"])
        self.assertEqual(["exit-02"], rule["auth_user"])
        self.assertEqual("openvpn-exit-02", rule["outbound"])

    def test_build_public_nodes_manifest_no_secrets(self):
        identities = {
            "exit-01": {
                "slot_id": "exit-01",
                "uuid": "11111111-2222-3333-4444-555555555555",
                "private_key": "SECRET_PRIV_KEY",
                "public_key": "PUBLIC_KEY_123456789012345678901234567",
                "short_id": "01234567",
            }
        }

        manifest = build_public_nodes_manifest(
            identities,
            public_host="198.51.100.1",
            reality_port=8443,
            sni="dl.google.com",
        )

        self.assertEqual("198.51.100.1", manifest["public_host"])
        self.assertEqual(1, len(manifest["nodes"]))

        node = manifest["nodes"][0]
        self.assertEqual("exit-01", node["slot_id"])
        self.assertEqual("198.51.100.1", node["address"])
        self.assertEqual(8443, node["port"])
        self.assertEqual("11111111-2222-3333-4444-555555555555", node["uuid"])
        self.assertEqual("PUBLIC_KEY_123456789012345678901234567", node["public_key"])
        self.assertEqual("01234567", node["short_id"])
        self.assertEqual("dl.google.com", node["sni"])
        self.assertIn("vless://11111111-2222-3333-4444-555555555555@198.51.100.1:8443?", node["link"])

        # Confirm NO private keys or passwords leaked in manifest
        raw_manifest_str = json.dumps(manifest)
        self.assertNotIn("SECRET_PRIV_KEY", raw_manifest_str)
        self.assertNotIn("private_key", raw_manifest_str)
        self.assertNotIn("password", raw_manifest_str)

    def test_check_sing_box_config_calls_subprocess(self):
        with patch("shutil.which", return_value="/usr/local/bin/sing-box"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                check_sing_box_config("/path/to/config.json", sing_box_bin="sing-box")
                mock_run.assert_called_once_with(
                    ["/usr/local/bin/sing-box", "check", "-c", "/path/to/config.json"],
                    capture_output=True,
                    text=True,
                )

    def test_gateway_auto_count_uses_runtime_profile(self):
        with patch.dict(os.environ, {"KUI_SLOT_COUNT": "auto"}, clear=True), patch(
            "vps.reality_gateway.resolve_runtime_profile"
        ) as profile:
            profile.return_value = type("Profile", (), {"slot_count": 4})()
            with tempfile.TemporaryDirectory() as tmpdir:
                workspace = Path(tmpdir) / "workspace"
                workspace.mkdir()
                (workspace / "internal_proxy.json").write_text(
                    json.dumps({"username": "gateway", "password": "gateway-password"}),
                    encoding="utf-8",
                )
                with patch.dict(
                    os.environ,
                    {
                        "KUI_SLOT_COUNT": "auto",
                        "KUI_INTERNAL_PROXY_WORKSPACE": str(workspace),
                        "KUI_REALITY_DATA_DIR": str(Path(tmpdir) / "data"),
                        "KUI_REALITY_NODES_FILE": str(Path(tmpdir) / "nodes.json"),
                        "KUI_PUBLIC_HOST": "198.51.100.42",
                    },
                    clear=True,
                ), patch("vps.reality_gateway.generate_x25519_keypair", return_value=("A" * 43, "B" * 43)), patch(
                    "vps.reality_gateway.shutil.which", return_value="/usr/local/bin/sing-box"
                ), patch("vps.reality_gateway.check_sing_box_config"):
                    result = run_gateway(do_exec=False)

        self.assertEqual(4, len(result["manifest"]["nodes"]))
        profile.assert_called_once()

    def test_run_gateway_no_exec(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir) / "data"
            nodes_file = Path(tmpdir) / "public-nodes.json"

            internal_workspace = Path(tmpdir) / "workspace"
            internal_workspace.mkdir()
            (internal_workspace / "internal_proxy.json").write_text(
                json.dumps({"username": "gateway", "password": "gateway-password"}),
                encoding="utf-8",
            )
            env_vars = {
                "KUI_SLOT_COUNT": "2",
                "KUI_REALITY_DATA_DIR": str(data_dir),
                "KUI_REALITY_NODES_FILE": str(nodes_file),
                "KUI_REALITY_PUBLIC_HOST": "198.51.100.42",
                "KUI_REALITY_SOCKS_HOST": "kui-local-multi-exit",
                "KUI_INTERNAL_PROXY_WORKSPACE": str(internal_workspace),
            }

            with patch.dict(os.environ, env_vars, clear=True), patch(
                "vps.reality_gateway.generate_x25519_keypair",
                return_value=("A" * 43, "B" * 43),
            ), patch(
                "vps.reality_gateway.shutil.which",
                return_value="/usr/local/bin/sing-box",
            ), patch("vps.reality_gateway.check_sing_box_config") as mock_check:
                res = run_gateway(do_exec=False)

            self.assertEqual("198.51.100.42", res["public_host"])
            self.assertTrue(Path(res["identities_file"]).exists())
            self.assertTrue(Path(res["config_file"]).exists())
            self.assertTrue(Path(res["nodes_file"]).exists())
            self.assertEqual(2, len(res["identities"]))
            self.assertEqual(2, len(res["manifest"]["nodes"]))
            self.assertEqual(1, len(res["config"]["inbounds"]))
            self.assertEqual(8443, res["manifest"]["nodes"][0]["port"])
            mock_check.assert_called_once()

            nodes_mode = oct(nodes_file.stat().st_mode & 0o777)
            self.assertEqual("0o644", nodes_mode)


if __name__ == "__main__":
    unittest.main()
