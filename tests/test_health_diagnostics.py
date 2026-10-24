import http.server
import json
import socket
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from tests.test_exit_manager import FakeListener, FakeProcess, FakeRouting
from vps.exit_manager import ExitManager
from vps.proxy_server import ProxyListener
from vps.store import LocalStore


class HealthDiagnosticsTest(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1] / "temp"
        root.mkdir(exist_ok=True)
        self.tempdir = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(self.tempdir.cleanup)
        self.workspace = Path(self.tempdir.name)
        (self.workspace / "internal_proxy.json").write_text(json.dumps({
            "version": 1, "username": "test-user", "password": "test@password",
        }))
        self.store = LocalStore(self.workspace / "state.db")
        self.store.initialize(slot_count=1)
        self.manager = ExitManager(self.store, routing=FakeRouting(), listener_factory=FakeListener,
                                   workspace=self.workspace, start_workers=False)
        self.slot = self.store.get_slot("exit-01")
        self.manager.commit_ready(self.slot.id, self.slot.generation, entry_ip="198.51.100.1",
                                  egress_ip="203.0.113.1", node={"country": "JP"}, check_result={})
        self.runtime = self.manager.runtime(self.slot.id)
        self.runtime.process = FakeProcess()
        self.runtime.worker = Mock(is_alive=Mock(return_value=True))
        self.manager.node_pool.penalize = Mock()

    def result(self, code="204", returncode=0, error=""):
        return Mock(stdout=code, returncode=returncode, stderr=error)

    def verify(self):
        return self.manager._verify_client_path(self.slot.id, self.store.get_slot(self.slot.id), self.slot.generation)

    def test_healthy_path_uses_one_socks_request_without_tun_or_reference(self):
        self.manager._run = Mock(return_value=self.result())
        with patch("vps.exit_manager.probe_health_reference") as reference:
            self.assertTrue(self.verify())
        self.manager._run.assert_called_once()
        command = self.manager._run.call_args.args[0]
        self.assertIn("-x", command)
        self.assertNotIn("--interface", command)
        self.assertNotIn("--doh-url", command)
        self.assertEqual(12, self.manager._run.call_args.kwargs["timeout"])
        reference.assert_not_called()

    def test_target_500_and_403_are_not_tunnel_failures_or_ai_unlock(self):
        self.manager._run = Mock(side_effect=[self.result("500"), self.result("403")])
        self.assertTrue(self.verify())
        current = self.store.get_slot(self.slot.id)
        self.assertEqual("ready", current.state)
        self.assertEqual("target_error", current.check_result["health"]["status"])
        self.assertEqual(["500", "403"], [a["code"] for a in current.check_result["health"]["attempts"]])
        self.assertFalse(current.check_result["health"]["attempts"][0]["ok"])
        self.assertFalse(current.check_result["health"]["attempts"][1]["ok"])
        self.assertEqual(0, current.failure_streak)
        self.manager.node_pool.penalize.assert_not_called()
        self.assertFalse(self.runtime.process.terminated)

    def test_primary_timeout_with_alternate_response_keeps_exit(self):
        self.manager._run = Mock(side_effect=[self.result("000", 28, "timeout"), self.result("200")])
        self.assertTrue(self.verify())
        self.assertEqual("ready", self.store.get_slot(self.slot.id).state)
        self.manager.node_pool.penalize.assert_not_called()

    def test_first_transport_failure_marks_degraded_without_redial(self):
        self.manager._run = Mock(return_value=self.result("000", 28, "timeout"))
        with patch.object(self.manager, "_handle_probe_failure") as recovery:
            self.assertFalse(self.verify())
        recovery.assert_not_called()
        current = self.store.get_slot(self.slot.id)
        self.assertEqual("degraded", current.state)
        self.assertEqual(2, len(current.check_result["health"]["attempts"]))
        self.assertEqual(0, current.failure_streak)
        self.assertTrue(self.runtime.listener.is_ready())

    def test_working_tun_with_failed_socks_does_not_change_vpn(self):
        self.manager._run = Mock(side_effect=[self.result("000", 28), self.result("000", 28), self.result()])
        self.assertFalse(self.verify())
        with patch("vps.exit_manager.probe_health_reference") as reference:
            self.assertFalse(self.manager._diagnose_client_failure(self.slot.id, self.slot.generation))
        reference.assert_not_called()
        self.assertEqual("local_proxy_path", self.store.get_slot(self.slot.id).check_result["health"]["status"])
        self.assertFalse(self.runtime.process.terminated)
        self.manager.node_pool.penalize.assert_not_called()
        self.assertIn("--interface", self.manager._run.call_args.args[0])

    def test_shared_outage_preserves_details_and_does_not_penalize_node(self):
        self.manager._run = Mock(return_value=self.result("000", 28, "timeout"))
        self.assertFalse(self.verify())
        with patch("vps.exit_manager.probe_health_reference", return_value={"ok": False, "error": "shared timeout"}):
            self.assertFalse(self.manager._diagnose_client_failure(self.slot.id, self.slot.generation))
        health = self.store.get_slot(self.slot.id).check_result["health"]
        self.assertEqual("shared_unavailable", health["status"])
        self.assertEqual(2, len(health["attempts"]))
        self.assertIn("tunnel", health)
        self.assertFalse(self.runtime.process.terminated)
        self.manager.node_pool.penalize.assert_not_called()

    def test_confirmed_socks_and_tun_failures_allow_exit_recovery(self):
        self.manager._run = Mock(return_value=self.result("000", 28, "timeout"))
        self.assertFalse(self.verify())
        with patch("vps.exit_manager.probe_health_reference", return_value={"ok": True}):
            self.assertTrue(self.manager._diagnose_client_failure(self.slot.id, self.slot.generation))
        self.assertEqual("failed", self.store.get_slot(self.slot.id).state)
        self.assertTrue(self.runtime.process is None or self.runtime.process.terminated)
        self.manager.node_pool.penalize.assert_called()

    def test_missing_credentials_are_not_vpn_failure(self):
        self.manager._run = Mock()
        with patch("vps.exit_manager.load_internal_proxy_credentials", side_effect=RuntimeError("not available")):
            self.assertFalse(self.verify())
        self.assertFalse(self.manager._diagnose_client_failure(self.slot.id, self.slot.generation))
        self.manager._run.assert_not_called()
        self.manager.node_pool.penalize.assert_not_called()
        self.assertEqual("local_configuration", self.store.get_slot(self.slot.id).check_result["health"]["status"])

    def test_proxy_auth_rejection_does_not_retry_other_targets_or_vpn(self):
        self.manager._run = Mock(return_value=self.result("000", 97, "User was rejected by the SOCKS5 server"))
        self.assertFalse(self.verify())
        self.assertFalse(self.manager._diagnose_client_failure(self.slot.id, self.slot.generation))
        self.manager._run.assert_called_once()
        self.manager.node_pool.penalize.assert_not_called()

    def test_alternate_auth_failure_is_not_misclassified_as_vpn_failure(self):
        self.manager._run = Mock(side_effect=[
            self.result("000", 28, "timeout"),
            self.result("000", 97, "User was rejected by the SOCKS5 server"),
        ])
        self.assertFalse(self.verify())
        self.assertFalse(self.manager._diagnose_client_failure(self.slot.id, self.slot.generation))
        self.assertEqual("local_configuration", self.store.get_slot(self.slot.id).check_result["health"]["status"])
        self.manager.node_pool.penalize.assert_not_called()
        self.assertEqual(2, self.manager._run.call_count)

    def test_cancelled_primary_does_not_launch_an_alternate_probe(self):
        def response(*_args, **_kwargs):
            self.store.update_slot(self.slot.id, enabled=False)
            return self.result("000", 28, "timeout")
        self.manager._run = Mock(side_effect=response)
        self.assertFalse(self.verify())
        self.manager._run.assert_called_once()
        self.assertFalse(self.store.get_slot(self.slot.id).enabled)

    def test_listener_repair_does_not_revive_a_manually_disabled_slot(self):
        self.runtime.listener.stop()
        self.store.update_slot(self.slot.id, enabled=False)
        self.assertFalse(self.manager._repair_listener(self.slot.id, self.slot.generation))
        self.assertFalse(self.runtime.listener.is_ready())
        self.assertFalse(self.store.get_slot(self.slot.id).enabled)

    def test_curl_stderr_does_not_expose_raw_or_encoded_credentials(self):
        self.manager._run = Mock(return_value=self.result("000", 28, "test-user:test@password test%40password"))
        self.assertFalse(self.verify())
        text = json.dumps(self.store.get_slot(self.slot.id).check_result)
        for secret in ("test-user", "test@password", "test%40password"):
            self.assertNotIn(secret, text)

    def test_subprocess_timeout_does_not_expose_full_argv(self):
        self.manager._run = Mock(side_effect=subprocess.TimeoutExpired(["curl", "test@password"], 12))
        self.assertFalse(self.verify())
        health = self.store.get_slot(self.slot.id).check_result["health"]
        self.assertEqual("TimeoutExpired", health["attempts"][0]["error"])
        self.assertNotIn("test@password", json.dumps(health))

    def test_late_response_cannot_restore_disabled_generation(self):
        def response(*_args, **_kwargs):
            self.store.update_slot(self.slot.id, enabled=False)
            return self.result()
        self.manager._run = Mock(side_effect=response)
        self.assertFalse(self.verify())
        self.assertFalse(self.store.get_slot(self.slot.id).enabled)

    def test_startup_failed_path_is_not_published_as_ready(self):
        self.manager.commit_ready(self.slot.id, self.slot.generation, entry_ip="198.51.100.1",
                                  egress_ip="203.0.113.1", node={"country": "JP"},
                                  check_result={"health": {"ok": False, "status": "local_configuration"}})
        self.assertEqual("degraded", self.store.get_slot(self.slot.id).state)
        self.assertEqual(0, self.store.get_slot(self.slot.id).failure_streak)

    def test_listener_repair_preserves_process_generation_and_entry(self):
        process = self.runtime.process
        self.runtime.listener.stop()
        self.manager.redial_slot = Mock()
        self.manager._try_recover_stale_slots()
        current = self.store.get_slot(self.slot.id)
        self.assertEqual("degraded", current.state)
        self.assertEqual(self.slot.generation, current.generation)
        self.assertEqual("198.51.100.1", current.entry_ip)
        self.assertIs(process, self.runtime.process)
        self.assertFalse(process.terminated)
        self.assertTrue(self.runtime.health_check_requested)
        self.manager.redial_slot.assert_not_called()

    def test_listener_repair_request_wakes_health_check_without_long_wait(self):
        self.runtime.health_check_requested = True
        with patch.object(self.runtime.stop, "wait") as wait:
            self.assertTrue(self.manager._wait_for_health_check(self.slot.id, self.slot.generation, self.runtime.stop, 300))
        wait.assert_not_called()
        self.assertFalse(self.runtime.health_check_requested)

    def test_real_socks_http_request_and_local_listener_repair(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(204)
                self.end_headers()
            def log_message(self, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        with socket.socket() as available:
            available.bind(("127.0.0.1", 0))
            port = available.getsockname()[1]
        with self.store._lock, self.store._connect() as c:
            c.execute("UPDATE exit_slots SET proxy_port=? WHERE id=?", (port, self.slot.id))
        self.runtime.listener.stop()
        self.runtime.listener = None
        self.manager.listener_factory = lambda sid, host, _port, interface, mark: ProxyListener(sid, "127.0.0.1", port, interface, mark)
        process = self.runtime.process
        target = f"http://127.0.0.1:{server.server_port}/generate_204"
        probe = self.manager._probe_target
        self.manager._probe_target = lambda slot, _url, **kwargs: probe(slot, target, **kwargs)
        self.manager._run = subprocess.run
        with patch.multiple("vps.proxy_server", PROXY_USER=b"test-user", PROXY_PASS=b"test@password",
                            _ADDITIONAL_PROXY_CREDENTIALS=(), CONNECTION_SLOTS=threading.BoundedSemaphore(4)), patch(
            "vps.proxy_server.create_connection", side_effect=lambda address, mark, timeout: socket.create_connection(address, timeout),
        ):
            try:
                self.assertTrue(self.manager._repair_listener(self.slot.id, self.slot.generation))
                self.assertTrue(self.verify())
                self.assertEqual("ready", self.store.get_slot(self.slot.id).state)
                self.runtime.listener.stop()
                self.manager._try_recover_stale_slots()
                self.assertEqual("degraded", self.store.get_slot(self.slot.id).state)
                self.assertTrue(self.verify())
                self.assertIs(process, self.runtime.process)
                self.assertFalse(process.terminated)
                self.assertEqual(self.slot.generation, self.store.get_slot(self.slot.id).generation)
            finally:
                self.runtime.listener.stop()


if __name__ == "__main__":
    unittest.main()
