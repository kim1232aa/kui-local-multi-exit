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

    def test_cleanup_is_idempotent_and_slot_scoped(self):
        self.routing.cleanup(self.first)
        self.routing.cleanup(self.first)

        commands = [" ".join(command) for command in self.recorder.commands]
        self.assertEqual(2, sum("route flush table 200" in command for command in commands))
        self.assertFalse(any("table 201" in command for command in commands))


if __name__ == "__main__":
    unittest.main()
