import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from vps.exit_manager import ExitManager
from vps.store import LocalStore


class DeploymentContractTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]

    def test_compose_publishes_all_fixed_slots_and_supports_optional_fetch_proxies(self):
        compose = (self.root / "compose.yaml").read_text(encoding="utf-8")
        self.assertIn('"127.0.0.1:7920-7943:7920-7943/tcp"', compose)
        self.assertIn('"127.0.0.1:7920-7943:7920-7943/udp"', compose)
        self.assertIn("KUI_FETCH_PROXY", compose)
        self.assertIn("KUI_OPENVPN_SOCKS_PROXY", compose)
        self.assertIn("KUI_ENABLE_VPNBOOK", compose)
        self.assertIn("KUI_VPN_HISTORY_DAYS", compose)
        self.assertIn("./providers:/opt/kui-providers:ro", compose)
        self.assertIn("./runtime/reality:/run/kui-reality:ro", compose)
        self.assertIn("KUI_REALITY_NODES_FILE", compose)
        self.assertIn("host.docker.internal:host-gateway", compose)

    def test_gitignore_excludes_runtime_credentials_configs_and_logs(self):
        ignored = (self.root / ".gitignore").read_text(encoding="utf-8")
        for marker in ("*.ovpn", "*.log", "auth.txt", "socks_auth.txt", "runtime/", ".env"):
            self.assertIn(marker, ignored)

    def test_dockerignore_excludes_repository_and_local_runtime_data(self):
        ignored = (self.root / ".dockerignore").read_text(encoding="utf-8")
        for marker in (".git", ".worktrees", ".env", "temp", "runtime", "*.db", "*.log"):
            self.assertIn(marker, ignored)

    def test_reality_gateway_installer_reuses_original_kui_protocol_shape(self):
        installer = self.root / "scripts" / "install-reality-gateway.sh"
        content = installer.read_text(encoding="utf-8")
        self.assertTrue(installer.stat().st_mode & stat.S_IXUSR)
        for marker in (
            'SING_BOX_VERSION="1.13.14"',
            '"type": "vless"',
            '"flow": "xtls-rprx-vision"',
            '"reality": {',
            '"type": "socks"',
            '"server": "127.0.0.1"',
            'generate", "reality-keypair',
            'NODE_COUNT=24',
            'PUBLIC_NODES_PATH',
            'systemctl enable --now kui-reality-gateway.service',
        ):
            self.assertIn(marker, content)

    def test_runtime_openvpn_config_and_log_are_owner_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = LocalStore(root / "state.db")
            store.initialize()
            store.update_slot("exit-01", enabled=True)
            manager = ExitManager(
                store,
                workspace=root / "runtime",
                start_workers=False,
                run=Mock(),
                popen=Mock(),
            )
            manager.config_dir.mkdir(parents=True)
            manager._write_runtime_file(manager.config_dir / "exit-01.ovpn", "client\n")
            manager._prepare_runtime_log(manager.workspace / "exit-01.log")

            config_mode = stat.S_IMODE(os.stat(manager.config_dir / "exit-01.ovpn").st_mode)
            log_mode = stat.S_IMODE(os.stat(manager.workspace / "exit-01.log").st_mode)
            self.assertEqual(0o600, config_mode)
            self.assertEqual(0o600, log_mode)


if __name__ == "__main__":
    unittest.main()
