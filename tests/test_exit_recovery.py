import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from tests.test_exit_manager import FakeListener, FakeProcess, FakeRouting
from vps.exit_manager import ExitManager
from vps.proxy_server import ProxyListener
from vps.store import LocalStore


class ExitRecoveryTest(unittest.TestCase):
    def setUp(self):
        temp_root = Path(__file__).resolve().parents[1] / "temp"
        temp_root.mkdir(exist_ok=True)
        self.tempdir = tempfile.TemporaryDirectory(dir=temp_root)
        self.addCleanup(self.tempdir.cleanup)
        reference = patch("vps.exit_manager.probe_health_reference", return_value={"ok": True})
        reference.start()
        self.addCleanup(reference.stop)
        self.store = LocalStore(Path(self.tempdir.name) / "state.db")
        self.store.initialize(slot_count=3)
        self.manager = ExitManager(
            self.store, routing=FakeRouting(), listener_factory=FakeListener,
            workspace=Path(self.tempdir.name), start_workers=False,
        )
        health_wait = patch.object(
            self.manager, "_wait_for_health_check",
            side_effect=lambda _sid, _gen, stop, delay: not stop.wait(delay),
        )
        health_wait.start()
        self.addCleanup(health_wait.stop)

    def ready_slot(self, slot_id="exit-01", age=0):
        generation = self.store.get_slot(slot_id).generation
        self.manager.commit_ready(
            slot_id, generation, entry_ip="198.51.100.1", egress_ip="203.0.113.1",
            node={"country": "JP"}, check_result={},
        )
        runtime = self.manager.runtime(slot_id)
        runtime.process = FakeProcess()
        runtime.worker = Mock(is_alive=Mock(return_value=True))
        with self.store._lock, self.store._connect() as db:
            db.execute("UPDATE exit_slots SET updated_at = ? WHERE id = ?", (int(time.time()) - age, slot_id))
        return runtime

    def test_all_ready_heartbeats_stale_without_any_fresh_slot_are_recovered(self):
        for slot_id in self.manager.managed_slot_ids:
            self.ready_slot(slot_id, age=240)
        self.manager.redial_slot = Mock()

        self.manager._try_recover_stale_slots()

        self.assertEqual(list(self.manager.managed_slot_ids), [call.args[0] for call in self.manager.redial_slot.call_args_list])

    def test_ready_runtime_failures_are_detected_without_waiting_for_heartbeat_timeout(self):
        for failure in ("worker", "listener", "process"):
            with self.subTest(failure=failure):
                runtime = self.ready_slot()
                if failure == "worker":
                    runtime.worker.is_alive.return_value = False
                elif failure == "listener":
                    runtime.listener.stop()
                else:
                    runtime.process.poll = lambda: 1
                self.manager.redial_slot = Mock()

                self.manager._try_recover_stale_slots()

                if failure == "listener":
                    self.manager.redial_slot.assert_not_called()
                    self.assertTrue(self.manager.listener_ready("exit-01"))
                    self.assertFalse(runtime.process.terminated)
                    self.assertEqual("degraded", self.store.get_slot("exit-01").state)
                else:
                    self.manager.redial_slot.assert_called_once_with("exit-01", automatic=True)

    def test_fresh_healthy_ready_slot_is_not_restarted(self):
        self.ready_slot()
        self.manager.redial_slot = Mock()
        self.manager._try_recover_stale_slots()
        self.manager.redial_slot.assert_not_called()

    def test_stuck_dial_is_recovered_but_semaphore_waiter_is_not(self):
        runtime = self.manager.runtime("exit-01")
        runtime.worker = Mock(is_alive=Mock(return_value=True))
        runtime.dial_started = time.monotonic() - 301
        self.store.set_runtime("exit-01", state="connecting")
        self.manager.redial_slot = Mock()

        self.manager._try_recover_stale_slots()
        self.manager.redial_slot.assert_called_once_with("exit-01", automatic=True)

        self.manager.redial_slot.reset_mock()
        runtime.dial_started = 0.0
        self.manager._try_recover_stale_slots()
        self.manager.redial_slot.assert_not_called()

    def test_expired_retry_timer_does_not_block_orphan_recovery(self):
        runtime = self.manager.runtime("exit-01")
        runtime.retry_timer = Mock(is_alive=Mock(return_value=False))
        self.manager.start_slot = Mock()

        self.manager._try_recover_idle_slots()

        self.assertIsNone(runtime.retry_timer)
        self.assertIn("exit-01", [call.args[0] for call in self.manager.start_slot.call_args_list])

    def test_one_slot_recovery_exception_does_not_skip_other_slots(self):
        def start(slot_id):
            if slot_id == "exit-01":
                raise RuntimeError("test recovery failure")
        self.manager.start_slot = Mock(side_effect=start)

        with self.assertLogs("vps.exit_manager", level="ERROR"):
            self.manager._try_recover_idle_slots()

        self.assertEqual(3, self.manager.start_slot.call_count)
        events = self.store.list_events(20)
        self.assertTrue(any(event["kind"] == "recovery_error" and "test recovery failure" in event["message"] for event in events))

    def test_auto_disabled_slot_is_not_revived_using_another_country(self):
        self.store.record_failure("exit-01", "no JP candidate", max_failures=1)
        self.manager.node_pool.replace([
            {"ip": "198.51.100.2", "country": "KR", "ping": 1, "score": 100, "config": "proto tcp\n"}
        ])
        self.manager.start_slot = Mock()

        self.manager._try_recover_auto_disabled_slots()

        self.assertFalse(self.store.get_slot("exit-01").enabled)
        self.manager.start_slot.assert_not_called()

    def test_manual_disable_is_respected(self):
        self.store.update_slot("exit-01", enabled=False)
        self.manager.node_pool.replace([
            {"ip": "198.51.100.2", "country": "JP", "ping": 1, "score": 100, "config": "proto tcp\n"}
        ])
        self.manager.start_slot = Mock()

        self.manager._try_recover_auto_disabled_slots()

        self.assertFalse(self.store.get_slot("exit-01").enabled)
        self.manager.start_slot.assert_not_called()

    def test_recovery_loop_survives_a_failed_phase_and_does_not_fetch_nodes(self):
        self.manager._shutdown = Mock()
        self.manager._shutdown.wait.side_effect = [False, True]
        self.manager._try_recover_auto_disabled_slots = Mock(side_effect=RuntimeError("test phase failure"))
        self.manager._try_recover_idle_slots = Mock()
        self.manager._try_recover_stale_slots = Mock()
        self.manager.refresh_nodes = Mock()

        with self.assertLogs("vps.exit_manager", level="ERROR"):
            self.manager._recovery_loop()

        self.manager._try_recover_idle_slots.assert_called_once()
        self.manager._try_recover_stale_slots.assert_called_once()
        self.manager.refresh_nodes.assert_not_called()
        self.assertTrue(all(call.args == (15,) for call in self.manager._shutdown.wait.call_args_list))

    def test_initialize_starts_recovery_independently_of_provider_refresh(self):
        self.manager.start_workers = True
        self.manager.refresh_nodes = Mock(return_value=0)
        self.manager.start_slot = Mock()
        with patch("vps.exit_manager.threading.Thread") as make_thread:
            self.manager.initialize()
        targets = {call.kwargs["target"] for call in make_thread.call_args_list}
        self.assertIn(self.manager._refresh_loop, targets)
        self.assertIn(self.manager._recovery_loop, targets)

    def test_provider_refresh_exception_does_not_kill_refresh_loop(self):
        self.manager._shutdown = Mock()
        self.manager._shutdown.wait.side_effect = [False, False, True]
        self.manager.refresh_nodes = Mock(side_effect=[RuntimeError("test refresh failure"), 0])
        with self.assertLogs("vps.exit_manager", level="ERROR"):
            self.manager._refresh_loop()
        self.assertEqual(2, self.manager.refresh_nodes.call_count)

    def test_403_is_recorded_as_target_error_not_successful_204_or_vpn_failure(self):
        self.ready_slot()
        (self.manager.workspace / "internal_proxy.json").write_text(
            '{"version":1,"username":"gateway","password":"test-password"}', encoding="utf-8"
        )
        self.manager._run = Mock(return_value=Mock(returncode=0, stdout="403", stderr=""))
        self.manager._handle_connection_failure = Mock()
        slot = self.store.get_slot("exit-01")

        self.assertTrue(self.manager._verify_client_path(slot.id, slot, slot.generation))

        self.manager._handle_connection_failure.assert_not_called()
        health = self.store.get_slot(slot.id).check_result["health"]
        self.assertEqual("target_error", health["status"])
        self.assertFalse(health["attempts"][0]["ok"])
        self.assertEqual("403", health["attempts"][0]["code"])

    def test_health_probe_interval_is_five_minutes_with_slot_stagger(self):
        runtime = self.ready_slot("exit-03")
        slot = self.store.get_slot("exit-03")
        runtime.stop = Mock(is_set=Mock(return_value=False))
        runtime.stop.wait.side_effect = [False, True]
        self.manager.routing.is_installed = Mock(return_value=True)
        self.manager._verify_client_path = Mock(return_value=True)
        self.manager._health_loop(slot.id, slot.generation, runtime.stop)
        self.assertEqual([(300.0,), (330.0,)], [call.args for call in runtime.stop.wait.call_args_list])

    def test_verify_missing_listener_does_not_leave_ready_slot_untouched(self):
        runtime = self.ready_slot()
        runtime.listener = None
        self.manager._handle_connection_failure = Mock()
        slot = self.store.get_slot("exit-01")

        self.assertFalse(self.manager._verify_client_path(slot.id, slot, slot.generation))

        self.manager._handle_connection_failure.assert_not_called()
        self.assertEqual("degraded", self.store.get_slot(slot.id).state)
        self.assertEqual("local_listener", self.store.get_slot(slot.id).check_result["health"]["status"])

    def test_watchdog_restores_real_socks_socket_after_listener_failure(self):
        with socket.socket() as available:
            available.bind(("127.0.0.1", 0))
            port = available.getsockname()[1]
        def listener_factory(slot_id, _host, _port, interface, mark):
            return ProxyListener(slot_id, "127.0.0.1", port, interface, mark)

        manager = ExitManager(
            self.store, routing=FakeRouting(), listener_factory=listener_factory,
            workspace=Path(self.tempdir.name), start_workers=True, slot_count=1,
        )
        errors = []

        # Only tunnel provisioning is simulated. Listener sockets, worker threads,
        # the watchdog loop and local socket repair are real; the VPN is retained.
        def provision(slot_id, generation):
            runtime = manager.runtime(slot_id)
            try:
                runtime.process = FakeProcess()
                manager.commit_ready(
                    slot_id, generation, entry_ip="198.51.100.1", egress_ip="203.0.113.1",
                    node={"country": "JP"}, check_result={},
                )
                runtime.stop.wait()
            except Exception as error:
                errors.append(error)

        manager._connect_worker = provision
        watchdog = threading.Thread(target=manager._recovery_loop, daemon=True)

        def wait_until(predicate):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if predicate():
                    return
                time.sleep(0.01)
            self.fail("watchdog did not restore the test listener")

        def check_socks_greeting():
            with socket.create_connection(("127.0.0.1", port), timeout=1) as client:
                client.sendall(b"\x05\x01\x02")
                self.assertEqual(b"\x05\x02", client.recv(2))

        try:
            with patch("vps.exit_manager.RECOVERY_INTERVAL_SECONDS", 0.02), patch.multiple(
                "vps.proxy_server", PROXY_USER=b"probe", PROXY_PASS=b"test-password"
            ):
                manager.start_slot("exit-01")
                wait_until(lambda: manager.listener_ready("exit-01"))
                check_socks_greeting()
                failed_listener = manager.runtime("exit-01").listener
                failed_listener.stop()
                self.assertFalse(failed_listener.is_ready())

                watchdog.start()
                wait_until(lambda: manager.runtime("exit-01").listener is not failed_listener and manager.listener_ready("exit-01"))
                check_socks_greeting()
                self.assertEqual("degraded", self.store.get_slot("exit-01").state)
                self.assertFalse(manager.runtime("exit-01").process.terminated)
                self.assertTrue(manager.runtime("exit-01").health_check_requested)
                self.assertFalse(errors)
                self.assertTrue(any(event["kind"] == "auto_recovery" for event in self.store.list_events(20)))
        finally:
            manager.shutdown()
            if watchdog.ident is not None:
                watchdog.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
