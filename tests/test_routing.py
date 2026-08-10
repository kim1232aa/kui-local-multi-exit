import tempfile
import unittest
from pathlib import Path

from vps.routing import RouteManager
from vps.store import LocalStore


class CommandRecorder:
    def __init__(self):
        self.commands = []

    def __call__(self, command, **kwargs):
        self.commands.append(command)

        class Result:
            returncode = 0
            stdout = ""
            stderr = ""

        return Result()


class SelectiveFailureRecorder(CommandRecorder):
    def __init__(self, failing_fragment, stderr="simulated route failure"):
        super().__init__()
        self.failing_fragment = failing_fragment
        self.stderr = stderr

    def __call__(self, command, **kwargs):
        result = super().__call__(command, **kwargs)
        if self.failing_fragment in " ".join(command):
            result.returncode = 2
            result.stderr = self.stderr
        return result


class RouteManagerTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        store = LocalStore(Path(self.tempdir.name) / "state.db")
        store.initialize()
        self.first = store.get_slot("exit-01")
        self.last = store.get_slot("exit-12")
        self.recorder = CommandRecorder()
        self.routing = RouteManager(run=self.recorder)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_slots_have_unique_route_tables_and_interfaces(self):
        self.routing.install(self.first, "198.51.100.1", "172.18.0.1", "eth0")
        self.routing.install(self.last, "198.51.100.12", "172.18.0.1", "eth0")

        commands = [" ".join(command) for command in self.recorder.commands]
        self.assertTrue(any("table 200" in command and "dev tun0" in command for command in commands))
        self.assertTrue(any("table 211" in command and "dev tun11" in command for command in commands))
        self.assertTrue(any("198.51.100.1/32 via 172.18.0.1 dev eth0" in command for command in commands))
        self.assertTrue(any("198.51.100.12/32 via 172.18.0.1 dev eth0" in command for command in commands))
        self.assertTrue(any("fwmark 200 unreachable pref 1200" in command for command in commands))
        self.assertTrue(any("fwmark 211 unreachable pref 1211" in command for command in commands))

    def test_cleanup_is_idempotent_and_slot_scoped(self):
        self.routing.cleanup(self.first)
        self.routing.cleanup(self.first)

        commands = [" ".join(command) for command in self.recorder.commands]
        self.assertEqual(2, sum("route flush table 200" in command for command in commands))
        self.assertEqual(2, sum("fwmark 200 unreachable pref 1200" in command for command in commands))
        self.assertFalse(any("table 201" in command for command in commands))

    def test_install_raises_when_required_route_command_fails(self):
        routing = RouteManager(run=SelectiveFailureRecorder("default dev tun0"))

        with self.assertRaisesRegex(RuntimeError, "simulated route failure"):
            routing.install(self.first, "198.51.100.1", "172.18.0.1", "eth0")

    def test_cleanup_ignores_known_missing_rules_but_not_unexpected_failures(self):
        missing = RouteManager(run=SelectiveFailureRecorder("rule del", "RTNETLINK answers: No such file or directory"))
        missing.cleanup(self.first)

        missing_table = RouteManager(run=SelectiveFailureRecorder("route flush", "Error: ipv4: FIB table does not exist"))
        missing_table.cleanup(self.first)

        unexpected_rule = RouteManager(run=SelectiveFailureRecorder("rule del", "RTNETLINK answers: Operation not permitted"))
        with self.assertRaisesRegex(RuntimeError, "Operation not permitted"):
            unexpected_rule.cleanup(self.first)

        unexpected_route = RouteManager(run=SelectiveFailureRecorder("route flush"))
        with self.assertRaisesRegex(RuntimeError, "simulated route failure"):
            unexpected_route.cleanup(self.first)

    def test_install_cleans_partial_routes_after_failure(self):
        recorder = SelectiveFailureRecorder("default dev tun0")
        routing = RouteManager(run=recorder)

        with self.assertRaises(RuntimeError):
            routing.install(self.first, "198.51.100.1", "172.18.0.1", "eth0")

        commands = [" ".join(command) for command in recorder.commands]
        self.assertEqual(2, sum("route flush table 200" in command for command in commands))

    def test_install_cleans_lookup_rule_if_fail_closed_rule_fails(self):
        recorder = SelectiveFailureRecorder("rule add fwmark 200 unreachable pref 1200")
        routing = RouteManager(run=recorder)

        with self.assertRaises(RuntimeError):
            routing.install(self.first, "198.51.100.1", "172.18.0.1", "eth0")

        commands = [" ".join(command) for command in recorder.commands]
        self.assertGreaterEqual(sum("rule del fwmark 200 lookup 200 pref 200" in command for command in commands), 1)
        self.assertGreaterEqual(sum("route flush table 200" in command for command in commands), 2)

    def test_is_installed_requires_default_route_on_slot_tunnel(self):
        class RouteStateRecorder(CommandRecorder):
            def __call__(self, command, **kwargs):
                result = super().__call__(command, **kwargs)
                if command == ["ip", "route", "show", "table", "200"]:
                    result.stdout = "198.51.100.1 via 172.18.0.1 dev eth0\n"
                return result

        routing = RouteManager(run=RouteStateRecorder())

        self.assertFalse(routing.is_installed(self.first))


if __name__ == "__main__":
    unittest.main()
