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

    def test_compose_uses_one_public_reality_port_and_internal_slot_routing(self):
        compose = (self.root / "compose.yaml").read_text(encoding="utf-8")
        self.assertIn("KUI_FETCH_PROXY", compose)
        self.assertIn("KUI_OPENVPN_SOCKS_PROXY", compose)
        self.assertIn("KUI_ENABLE_VPNBOOK", compose)
        self.assertIn("KUI_ALLOW_NON_RESIDENTIAL", compose)
        self.assertIn("KUI_VPN_HISTORY_DAYS", compose)
        self.assertIn("KUI_SLOT_COUNT", compose)
        self.assertIn("KUI_DIAL_WORKERS", compose)
        self.assertIn("PROXY_MAX_CONNECTIONS", compose)
        self.assertIn("KUI_INTERNAL_PROXY_USER", compose)
        self.assertIn("KUI_INTERNAL_PROXY_PASSWORD", compose)
        self.assertIn("./providers:/opt/kui-providers:ro", compose)
        self.assertIn("./runtime/reality:/run/kui-reality:ro", compose)
        self.assertIn("KUI_REALITY_NODES_FILE", compose)
        self.assertIn("host.docker.internal:host-gateway", compose)
        self.assertIn("kui-reality-gateway:", compose)
        self.assertIn("kui-reality-data:", compose)
        self.assertIn('"${KUI_REALITY_PORT:-8443}:${KUI_REALITY_PORT:-8443}/tcp"', compose)
        self.assertNotIn("7920-7943:7920-7943", compose)
        self.assertNotIn("7920-7953:7920-7953", compose)
        self.assertNotIn("8443-8466:8443-8466", compose)
        self.assertNotIn("8443-8476:8443-8476", compose)
        self.assertIn('command: ["python3", "-m", "vps.reality_gateway"]', compose)
        self.assertIn("kui-local-data:/opt/kui-local:ro", compose)
        self.assertIn("./runtime/reality:/run/kui-reality:rw", compose)
        self.assertNotIn("kui-cloudshell-origin", compose)
        self.assertNotIn("kui-cloudflared", compose)
        self.assertNotIn("kui-cloudshell-secrets", compose)
        self.assertNotIn("cloudflare/cloudflared", compose)
        self.assertNotIn("38080:38080", compose)
        self.assertNotIn("38081:38081", compose)
        self.assertNotIn("38090-38113", compose)
        self.assertIn("healthcheck:", compose)
        self.assertIn("/proc/net/tcp", compose)
        self.assertNotIn("socket.create_connection", compose)
        self.assertIn("service_healthy", compose)

    def test_dockerfile_exposes_only_management_and_default_reality_ports(self):
        dockerfile = (self.root / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("EXPOSE 8080 8443", dockerfile)
        self.assertNotIn("7920-7943", dockerfile)
        self.assertNotIn("8443-8466", dockerfile)

    def test_dockerfile_selects_matching_sing_box_architecture(self):
        dockerfile = (self.root / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("ARG TARGETARCH", dockerfile)
        self.assertIn("amd64|arm64", dockerfile)
        self.assertIn("linux-${TARGETARCH}.tar.gz", dockerfile)
        self.assertNotIn("linux-amd64.tar.gz\"", dockerfile)

    def test_gitignore_excludes_runtime_credentials_configs_and_logs(self):
        ignored = (self.root / ".gitignore").read_text(encoding="utf-8")
        for marker in ("*.ovpn", "*.log", "auth.txt", "socks_auth.txt", "internal_proxy.json", "runtime/", ".env"):
            self.assertIn(marker, ignored)

    def test_dockerignore_excludes_repository_and_local_runtime_data(self):
        ignored = (self.root / ".dockerignore").read_text(encoding="utf-8")
        for marker in (".git", ".worktrees", ".env", "temp", "runtime", "*.db", "*.log", "internal_proxy.json"):
            self.assertIn(marker, ignored)

    def test_no_host_reality_gateway_installer(self):
        installer = self.root / "scripts" / "install-reality-gateway.sh"
        self.assertFalse(installer.exists(), "Reality gateway must run inside Docker, not as a host systemd service")

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
