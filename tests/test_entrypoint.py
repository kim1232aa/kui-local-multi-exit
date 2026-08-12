import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vps.entrypoint import Application, build_application, clear_proxy_environment
from vps.runtime_profile import RuntimeProfile
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
        self.assertEqual(23, len(enabled_ids))

    def test_build_application_applies_runtime_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            profile = RuntimeProfile(
                slot_count=2,
                dial_workers=1,
                max_connections=32,
                memory_bytes=1024**3,
                memory_source="test",
            )
            with patch.dict(
                os.environ,
                {
                    "KUI_WORKSPACE": str(workspace),
                    "KUI_MANAGEMENT_PASSWORD": "test-password",
                    "KUI_MANAGEMENT_PORT": "0",
                },
                clear=True,
            ), patch("vps.entrypoint.resolve_runtime_profile", return_value=profile), patch(
                "vps.entrypoint.configure_connection_limit"
            ) as configure_limit:
                application = build_application()
            try:
                self.assertEqual(("exit-01", "exit-02"), application.manager.managed_slot_ids)
                self.assertEqual(1, application.manager._dial_slots._value)
                configure_limit.assert_called_once_with(32)
            finally:
                application.server.server_close()

    def test_bridge_refresh_uses_runtime_dial_worker_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            profile = RuntimeProfile(
                slot_count=2,
                dial_workers=1,
                max_connections=32,
                memory_bytes=1024**3,
                memory_source="test",
            )
            with patch.dict(
                os.environ,
                {
                    "KUI_WORKSPACE": str(workspace),
                    "KUI_MANAGEMENT_PASSWORD": "test-password",
                    "KUI_MANAGEMENT_PORT": "0",
                    "KUI_BRIDGE_SUB_URLS": "https://example.com/subscription",
                },
                clear=True,
            ), patch("vps.entrypoint.resolve_runtime_profile", return_value=profile), patch(
                "vps.entrypoint.start_background_refresh"
            ) as refresh:
                application = build_application()
            try:
                refresh.assert_called_once_with(
                    interval=300,
                    manual_urls=[],
                    subscription_urls=["https://example.com/subscription"],
                    enable_speed_test=False,
                    top_n=16,
                    max_workers=1,
                )
            finally:
                application.server.server_close()

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
