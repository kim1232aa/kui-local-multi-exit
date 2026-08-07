import tempfile
import unittest
from pathlib import Path

from vps.realm_manager import RealmManager, RealmUnavailable
from vps.store import LocalStore


class FakeProcess:
    def __init__(self, *, returncode=None):
        self.returncode = returncode
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


class RealmManagerTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = LocalStore(Path(self.tempdir.name) / "state.db")
        self.store.initialize()
        self.calls = []

        def popen(command, **kwargs):
            process = FakeProcess()
            self.calls.append((command, kwargs, process))
            return process

        self.manager = RealmManager(
            self.store,
            binary="/usr/local/bin/realm",
            popen=popen,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_configure_persists_validated_mapping(self):
        configured = self.manager.configure(
            {"listen": "0.0.0.0:5000", "remote": "example.com:443", "use_udp": True}
        )
        reopened = RealmManager(
            self.store,
            binary="/usr/local/bin/realm",
            popen=lambda *args, **kwargs: FakeProcess(),
        )

        self.assertEqual("0.0.0.0:5000", configured["listen"])
        self.assertEqual("example.com:443", configured["remote"])
        self.assertTrue(configured["use_udp"])
        self.assertEqual("0.0.0.0:5000", reopened.status()["listen"])
        self.assertEqual("example.com:443", reopened.status()["remote"])

    def test_configure_rejects_invalid_listen_and_remote_endpoints(self):
        invalid = (
            {"listen": "example.com:5000", "remote": "1.1.1.1:443"},
            {"listen": "0.0.0.0", "remote": "1.1.1.1:443"},
            {"listen": "0.0.0.0:5000", "remote": "bad host:443"},
            {"listen": "0.0.0.0:5000", "remote": "1.1.1.1:70000"},
        )
        for payload in invalid:
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    self.manager.configure(payload)

    def test_start_uses_argument_vector_and_reports_running_process(self):
        self.manager.configure(
            {"listen": "0.0.0.0:5000", "remote": "1.1.1.1:443", "use_udp": True}
        )

        status = self.manager.start()

        self.assertEqual(
            ["/usr/local/bin/realm", "-u", "-l", "0.0.0.0:5000", "-r", "1.1.1.1:443"],
            self.calls[0][0],
        )
        self.assertNotIn("shell", self.calls[0][1])
        self.assertTrue(status["running"])
        self.assertEqual("running", status["state"])

    def test_start_failure_is_reported_without_fake_running_state(self):
        def failing_popen(command, **kwargs):
            raise OSError("permission denied")

        manager = RealmManager(
            self.store,
            binary="/usr/local/bin/realm",
            popen=failing_popen,
        )
        manager.configure({"listen": "0.0.0.0:5000", "remote": "1.1.1.1:443"})

        with self.assertRaisesRegex(RuntimeError, "permission denied"):
            manager.start()

        self.assertFalse(manager.status()["running"])
        self.assertEqual("failed", manager.status()["state"])
        self.assertIn("permission denied", manager.status()["error"])

    def test_missing_binary_reports_unavailable(self):
        manager = RealmManager(self.store, binary=None, which=lambda _name: None)
        manager.configure({"listen": "0.0.0.0:5000", "remote": "1.1.1.1:443"})

        with self.assertRaisesRegex(RealmUnavailable, "realm binary is not installed"):
            manager.start()

        self.assertFalse(manager.status()["available"])
        self.assertEqual("unavailable", manager.status()["state"])

    def test_stop_is_idempotent_and_restart_replaces_process(self):
        self.manager.configure({"listen": "0.0.0.0:5000", "remote": "1.1.1.1:443"})
        first = self.manager.start()
        first_process = self.calls[0][2]

        second = self.manager.restart()
        stopped = self.manager.stop()
        stopped_again = self.manager.stop()

        self.assertTrue(first["running"])
        self.assertTrue(first_process.terminated)
        self.assertTrue(second["running"])
        self.assertEqual(2, len(self.calls))
        self.assertFalse(stopped["running"])
        self.assertEqual("stopped", stopped_again["state"])


if __name__ == "__main__":
    unittest.main()
