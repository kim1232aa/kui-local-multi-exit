import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


class InstallScriptTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        self.script = self.root / "install.sh"
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.bin = self.work / "bin"
        self.bin.mkdir()
        self.install_dir = self.work / "install"
        self.log = self.work / "commands.log"
        self.os_release = self.work / "os-release"
        self.os_release.write_text(
            'ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n',
            encoding="utf-8",
        )
        self._write_executable(
            "id",
            """
            #!/bin/sh
            [ "${1:-}" = "-u" ] && { echo 0; exit 0; }
            exec /usr/bin/id "$@"
            """,
        )
        self._write_executable(
            "git",
            """
            #!/bin/sh
            printf 'git %s\n' "$*" >> "$KUI_TEST_LOG"
            if [ "$1" = "clone" ]; then
                dest=""
                for arg in "$@"; do dest="$arg"; done
                mkdir -p "$dest/.git"
                : > "$dest/compose.yaml"
            fi
            exit 0
            """,
        )
        self._write_executable(
            "curl",
            """
            #!/bin/sh
            printf 'curl %s\n' "$*" >> "$KUI_TEST_LOG"
            output=""
            previous=""
            for arg in "$@"; do
                [ "$previous" != "-o" ] || output="$arg"
                previous="$arg"
            done
            if [ -n "$output" ]; then
                mkdir -p "$(dirname "$output")"
                printf 'fake-download\n' > "$output"
                exit 0
            fi
            case "$*" in
                *127.0.0.1*/healthz*) printf '{"ok":true}\n' ;;
                *https://*) exit 0 ;;
            esac
            exit 0
            """,
        )
        self._write_docker()

    def _write_executable(self, name: str, body: str) -> Path:
        path = self.bin / name
        path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
        path.chmod(0o755)
        return path

    def _write_docker(self) -> None:
        self._write_executable(
            "docker",
            """
            #!/bin/sh
            printf 'docker %s\\n' "$*" >> "$KUI_TEST_LOG"
            case "$*" in
                "compose version")
                    if [ "${KUI_TEST_COMPOSE_MISSING:-0}" = "1" ] && [ ! -f "${KUI_TEST_COMPOSE_STATE:-}" ]; then
                        exit 1
                    fi
                    echo 'Docker Compose version v2.30.0'
                    ;;
                "info") : ;;
                "compose ps -q "*) echo service-id ;;
                "inspect --format "*) echo healthy ;;
                "compose exec -T kui-reality-gateway kui-sing-box check -c /var/lib/kui-reality/config.json") : ;;
            esac
            exit 0
            """,
        )

    def _run(self, *args: str, extra_env: dict[str, str] | None = None):
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{self.bin}:/usr/bin:/bin",
                "KUI_INSTALL_DIR": str(self.install_dir),
                "KUI_OS_RELEASE_FILE": str(self.os_release),
                "KUI_ETC_DIR": str(self.work / "etc"),
                "KUI_TUN_DEVICE": "/dev/null",
                "KUI_TEST_LOG": str(self.log),
                "KUI_HEALTH_TIMEOUT": "1",
                "KUI_HEALTH_INTERVAL": "1",
            }
        )
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["/bin/sh", str(self.script), *args],
            cwd=self.root,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )

    def test_fresh_install_generates_private_env_and_starts_core_services(self):
        result = self._run("--public-host", "vpn.example.com", "--slot-count", "34")

        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        env_path = self.install_dir / ".env"
        self.assertTrue(env_path.is_file())
        self.assertEqual(0o600, stat.S_IMODE(env_path.stat().st_mode))
        values = dict(
            line.split("=", 1)
            for line in env_path.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        )
        self.assertEqual("vpn.example.com", values["KUI_PUBLIC_HOST"])
        self.assertEqual("34", values["KUI_SLOT_COUNT"])
        self.assertGreaterEqual(len(values["KUI_MANAGEMENT_PASSWORD"]), 32)
        self.assertNotIn(values["KUI_MANAGEMENT_PASSWORD"], result.stdout)
        self.assertIn("将安装缺失的 Docker", result.stdout)
        self.assertIn("不会修改防火墙", result.stdout)
        commands = self.log.read_text(encoding="utf-8")
        self.assertIn(
            "docker compose up -d --build kui-local-multi-exit kui-reality-gateway",
            commands,
        )
        self.assertNotIn("docker compose up -d --build\n", commands)
        self.assertIn("安装完成", result.stdout)

    def test_rerun_preserves_env_and_fast_forwards_existing_checkout(self):
        (self.install_dir / ".git").mkdir(parents=True)
        (self.install_dir / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
        original = (
            "KUI_MANAGEMENT_PASSWORD=keep-this-secret\n"
            "KUI_MANAGEMENT_PORT=18080\n"
            "KUI_REALITY_PORT=18443\n"
        )
        (self.install_dir / ".env").write_text(original, encoding="utf-8")

        result = self._run()

        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        self.assertEqual(original, (self.install_dir / ".env").read_text(encoding="utf-8"))
        commands = self.log.read_text(encoding="utf-8")
        self.assertIn(f"git -C {self.install_dir} pull --ff-only", commands)
        self.assertIn("http://127.0.0.1:18080/healthz", commands)
        self.assertIn("Reality 端口：18443/tcp", result.stdout)
        self.assertNotIn(" down ", commands)
        self.assertNotIn(" -v", commands)

    def test_missing_docker_is_installed_from_official_apt_repository(self):
        (self.bin / "docker").unlink()
        system_bin = self.work / "system-bin"
        system_bin.mkdir()
        for name in ("cat", "chmod", "cp", "dirname", "mkdir", "od", "openssl", "sleep", "tr"):
            source = shutil.which(name)
            if source:
                (system_bin / name).symlink_to(source)
        docker_template = self.work / "docker-template"
        docker_template.write_text(
            "#!/bin/sh\n"
            "printf 'docker %s\\n' \"$*\" >> \"$KUI_TEST_LOG\"\n"
            "case \"$*\" in \"compose version\") : ;; \"info\") : ;; \"compose ps -q \"*) echo service-id ;; \"inspect --format \"*) echo healthy ;; esac\n",
            encoding="utf-8",
        )
        docker_template.chmod(0o755)
        self._write_executable(
            "apt-get",
            """
            #!/bin/sh
            printf 'apt-get %s\n' "$*" >> "$KUI_TEST_LOG"
            case "$*" in
                *docker-ce*)
                    cp "$KUI_TEST_DOCKER_TEMPLATE" "$KUI_SYSTEM_BIN/docker"
                    chmod 755 "$KUI_SYSTEM_BIN/docker"
                    ;;
            esac
            exit 0
            """,
        ).replace(system_bin / "apt-get")
        self._write_executable(
            "install",
            """
            #!/bin/sh
            printf 'install %s\n' "$*" >> "$KUI_TEST_LOG"
            destination=""
            for arg in "$@"; do destination="$arg"; done
            mkdir -p "$destination"
            exit 0
            """,
        ).replace(system_bin / "install")
        self._write_executable(
            "dpkg",
            """
            #!/bin/sh
            [ "$1" = "--print-architecture" ] && echo amd64
            """,
        ).replace(system_bin / "dpkg")

        result = self._run(
            extra_env={
                "PATH": str(self.bin),
                "KUI_SYSTEM_BIN": str(system_bin),
                "KUI_MACHINE_ARCH": "x86_64",
                "KUI_TEST_DOCKER_TEMPLATE": str(docker_template),
            }
        )

        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        commands = self.log.read_text(encoding="utf-8")
        self.assertIn("curl -fsSL https://download.docker.com/linux/debian/gpg", commands)
        self.assertIn("apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin", commands)

    def test_existing_docker_without_curl_installs_curl(self):
        curl_template = self.bin / "curl"
        system_bin = self.work / "system-bin"
        system_bin.mkdir()
        for name in ("cat", "chmod", "cp", "dirname", "mkdir", "openssl", "sed", "sleep", "tail", "tr"):
            source = shutil.which(name)
            if source:
                (system_bin / name).symlink_to(source)
        self._write_executable(
            "apt-get",
            """
            #!/bin/sh
            printf 'apt-get %s\n' "$*" >> "$KUI_TEST_LOG"
            case "$*" in
                *curl*) cp "$KUI_TEST_CURL_TEMPLATE" "$KUI_SYSTEM_BIN/curl" ;;
            esac
            exit 0
            """,
        ).replace(system_bin / "apt-get")
        curl_template.replace(self.work / "curl-template")

        result = self._run(
            extra_env={
                "PATH": str(self.bin),
                "KUI_SYSTEM_BIN": str(system_bin),
                "KUI_MACHINE_ARCH": "x86_64",
                "KUI_TEST_CURL_TEMPLATE": str(self.work / "curl-template"),
            }
        )

        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        commands = self.log.read_text(encoding="utf-8")
        self.assertIn("apt-get install -y ca-certificates curl", commands)

    def test_existing_docker_without_compose_installs_compose_plugin(self):
        compose_state = self.work / "compose-installed"
        self._write_executable(
            "apt-get",
            """
            #!/bin/sh
            printf 'apt-get %s\n' "$*" >> "$KUI_TEST_LOG"
            case "$*" in
                *docker-compose-plugin*) : > "$KUI_TEST_COMPOSE_STATE" ;;
            esac
            exit 0
            """,
        )

        result = self._run(
            extra_env={
                "KUI_TEST_COMPOSE_MISSING": "1",
                "KUI_TEST_COMPOSE_STATE": str(compose_state),
            }
        )

        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        commands = self.log.read_text(encoding="utf-8")
        self.assertIn("curl -fsSL https://download.docker.com/linux/debian/gpg", commands)
        self.assertIn(
            "apt-get install -y docker-buildx-plugin docker-compose-plugin",
            commands,
        )

    def test_unsupported_cpu_architecture_stops_before_clone(self):
        result = self._run(extra_env={"KUI_MACHINE_ARCH": "riscv64"})

        self.assertNotEqual(0, result.returncode)
        self.assertIn("CPU", result.stderr + result.stdout)
        self.assertFalse(self.install_dir.exists())

    def test_public_host_rejects_shell_and_env_injection_characters(self):
        result = self._run("--public-host", "vpn.example.com\nKUI_SLOT_COUNT=1")

        self.assertNotEqual(0, result.returncode)
        self.assertIn("--public-host", result.stderr + result.stdout)
        self.assertFalse(self.install_dir.exists())

    def test_invalid_polling_settings_stop_before_clone(self):
        invalid_settings = (
            ("KUI_HEALTH_TIMEOUT", "not-a-number"),
            ("KUI_HEALTH_TIMEOUT", "10ms"),
            ("KUI_HEALTH_INTERVAL", "0"),
            ("KUI_HEALTH_INTERVAL", "08"),
        )
        for variable, value in invalid_settings:
            with self.subTest(variable=variable, value=value):
                shutil.rmtree(self.install_dir, ignore_errors=True)
                self.log.unlink(missing_ok=True)

                result = self._run(extra_env={variable: value})

                self.assertNotEqual(0, result.returncode)
                self.assertIn(variable, result.stderr + result.stdout)
                self.assertFalse(self.install_dir.exists())

    def test_regular_file_is_not_accepted_as_tun_device(self):
        fake_tun = self.work / "tun"
        fake_tun.write_text("not-a-device", encoding="utf-8")

        result = self._run(extra_env={"KUI_TUN_DEVICE": str(fake_tun)})

        self.assertNotEqual(0, result.returncode)
        self.assertIn("TUN", result.stderr + result.stdout)
        self.assertFalse(self.install_dir.exists())

    def test_missing_tun_stops_before_clone(self):
        result = self._run(extra_env={"KUI_TUN_DEVICE": str(self.work / "missing-tun")})

        self.assertNotEqual(0, result.returncode)
        self.assertIn("TUN", result.stderr + result.stdout)
        self.assertFalse(self.install_dir.exists())
        self.assertFalse(self.log.exists())

    def test_unsupported_distribution_stops_before_clone(self):
        self.os_release.write_text("ID=centos\nVERSION_ID=9\n", encoding="utf-8")

        result = self._run()

        self.assertNotEqual(0, result.returncode)
        self.assertIn("仅支持 Debian/Ubuntu", result.stderr + result.stdout)
        self.assertFalse(self.install_dir.exists())
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
