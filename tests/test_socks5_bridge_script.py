import json
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


class Socks5BridgeScriptTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        self.script = self.root / "vps" / "socks5-bridge.sh"
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.bin = self.work / "bin"
        self.bin.mkdir()
        self.log = self.work / "docker.log"
        self.exits = self.work / "exits.json"
        self.exits.write_text(
            json.dumps(
                {
                    "exits": [
                        {
                            "id": f"exit-{index:02d}",
                            "proxy_port": 7919 + index,
                            "country": "JP",
                            "state": "ready" if index == 1 else "connecting",
                        }
                        for index in range(1, 35)
                    ]
                }
            ),
            encoding="utf-8",
        )
        self._write_executable(
            "docker",
            """
            #!/bin/sh
            printf '%s\n' "$*" >> "$KUI_TEST_DOCKER_LOG"
            case "$*" in
                "info") exit 0 ;;
                "exec kui-local-multi-exit cat /opt/kui-local/internal_proxy.json")
                    printf '{"username":"internal","password":"internal-secret"}\n'
                    ;;
                "inspect kui-local-multi-exit --format "*) printf 'test-network\n' ;;
            esac
            exit 0
            """,
        )
        self._write_executable(
            "curl",
            """
            #!/bin/sh
            case "$*" in
                */api/local/exits*) cat "$KUI_TEST_EXITS" ;;
                *) printf '198.51.100.1\n' ;;
            esac
            """,
        )

    def _write_executable(self, name: str, body: str) -> Path:
        path = self.bin / name
        path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
        path.chmod(0o755)
        return path

    def _run_script(self) -> Path:
        state_dir = self.work / "state"
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{self.bin}:/usr/bin:/bin",
                "DOCKER": str(self.bin / "docker"),
                "KUI_MANAGEMENT_PASSWORD": "management-secret",
                "KUI_BASE_URL": "http://127.0.0.1:18080",
                "BRIDGE_NAME": "gcs-bridge",
                "BRIDGE_STATE_DIR": str(state_dir),
                "KUI_TEST_DOCKER_LOG": str(self.log),
                "KUI_TEST_EXITS": str(self.exits),
                "SKIP_VERIFY": "1",
            }
        )

        result = subprocess.run(
            ["bash", str(self.script)],
            cwd=self.root,
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        return state_dir

    def test_publishes_all_managed_slots_even_when_some_are_not_ready(self):
        state_dir = self._run_script()
        config = json.loads((state_dir / "config.json").read_text(encoding="utf-8"))
        slot_ports = sorted(
            inbound["listen_port"]
            for inbound in config["inbounds"]
            if inbound["tag"].startswith("exit-")
        )
        self.assertEqual(list(range(7920, 7954)), slot_ports)
        docker_log = self.log.read_text(encoding="utf-8")
        self.assertIn("-p 7920-7953:7920-7953", docker_log)

    def test_writes_config_with_owner_only_permissions(self):
        state_dir = self._run_script()
        self.assertEqual(0o600, (state_dir / "config.json").stat().st_mode & 0o777)


if __name__ == "__main__":
    unittest.main()
