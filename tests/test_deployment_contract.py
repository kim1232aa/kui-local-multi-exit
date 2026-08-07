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
        self.assertIn('"7920-7931:7920-7931"', compose)
        self.assertIn("KUI_FETCH_PROXY", compose)
        self.assertIn("KUI_OPENVPN_SOCKS_PROXY", compose)
        self.assertIn("host.docker.internal:host-gateway", compose)

    def test_gitignore_excludes_runtime_credentials_configs_and_logs(self):
        ignored = (self.root / ".gitignore").read_text(encoding="utf-8")
        for marker in ("*.ovpn", "*.log", "auth.txt", "socks_auth.txt", "runtime/"):
            self.assertIn(marker, ignored)

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
