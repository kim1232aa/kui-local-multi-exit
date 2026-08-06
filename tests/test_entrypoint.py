import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vps.entrypoint import Application, clear_proxy_environment
from vps.store import LocalStore


class FakeManager:
    def __init__(self):
        self.initialized = False
        self.shutdown_called = False

    def initialize(self):
        self.initialized = True

    def shutdown(self):
        self.shutdown_called = True


class FakeServer:
    def __init__(self):
        self.served = False
        self.shutdown_called = False
        self.closed = False

    def serve_forever(self):
        self.served = True

    def shutdown(self):
        self.shutdown_called = True

    def server_close(self):
        self.closed = True


class ApplicationTest(unittest.TestCase):
    def test_start_initializes_manager_before_serving_api(self):
        order = []

        class OrderedManager(FakeManager):
            def initialize(self):
                order.append("manager")

        class OrderedServer(FakeServer):
            def serve_forever(self):
                order.append("server")

        application = Application(OrderedManager(), OrderedServer())
        application.run()

        self.assertEqual(["manager", "server"], order)

    def test_shutdown_cleans_manager_and_http_server(self):
        manager = FakeManager()
        server = FakeServer()
        application = Application(manager, server)

        application.shutdown()

        self.assertTrue(manager.shutdown_called)
        self.assertTrue(server.shutdown_called)
        self.assertTrue(server.closed)

    def test_disabled_slots_are_persisted_for_manager_to_skip(self):
        with tempfile.TemporaryDirectory() as directory:
            store = LocalStore(Path(directory) / "state.db")
            store.initialize()
            store.update_slot("exit-01", enabled=False)

            enabled_ids = [slot.id for slot in store.list_slots() if slot.enabled]

        self.assertNotIn("exit-01", enabled_ids)
        self.assertEqual(11, len(enabled_ids))

    def test_proxy_environment_is_removed_before_network_startup(self):
        variables = {
            "HTTP_PROXY": "http://127.0.0.1:9",
            "https_proxy": "http://127.0.0.1:9",
            "ALL_PROXY": "socks5://127.0.0.1:9",
            "NO_PROXY": "localhost",
        }
        with patch.dict(os.environ, variables, clear=True):
            clear_proxy_environment()
            remaining = dict(os.environ)

        self.assertNotIn("HTTP_PROXY", remaining)
        self.assertNotIn("https_proxy", remaining)
        self.assertNotIn("ALL_PROXY", remaining)
        self.assertNotIn("NO_PROXY", remaining)


if __name__ == "__main__":
    unittest.main()
