import concurrent.futures
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from tests.test_exit_manager import FakeListener, FakeProcess, FakeRouting
from vps.exit_manager import ExitManager
from vps.store import LocalStore
from vps.vpngate import NodePool, probe_health_reference


class ExitStabilityTest(unittest.TestCase):
    def setUp(self):
        temp_root = Path(__file__).resolve().parents[1] / "temp"
        temp_root.mkdir(exist_ok=True)
        self.tempdir = tempfile.TemporaryDirectory(dir=temp_root)
        self.addCleanup(self.tempdir.cleanup)
        self.workspace = Path(self.tempdir.name)
        self.store = LocalStore(self.workspace / "state.db")
        self.store.initialize(slot_count=3)
        self.manager = ExitManager(
            self.store, routing=FakeRouting(), listener_factory=FakeListener,
            workspace=self.workspace, start_workers=False,
        )
        health_wait = patch.object(
            self.manager, "_wait_for_health_check",
            side_effect=lambda _sid, _gen, stop, delay: not stop.wait(delay),
        )
        health_wait.start()
        self.addCleanup(health_wait.stop)
        (self.workspace / "internal_proxy.json").write_text(
            '{"version":1,"username":"test-gateway","password":"test-password"}', encoding="utf-8"
        )

    def ready_slot(self, slot_id="exit-01"):
        generation = self.store.get_slot(slot_id).generation
        self.manager.commit_ready(
            slot_id, generation, entry_ip="198.51.100.1", egress_ip="203.0.113.1",
            node={"country": "JP"}, check_result={},
        )
        runtime = self.manager.runtime(slot_id)
        runtime.process = FakeProcess()
        runtime.worker = Mock(is_alive=Mock(return_value=True))
        return runtime

    def test_shared_probe_outage_keeps_tunnels_but_marks_them_degraded(self):
        runtimes = [self.ready_slot(sid) for sid in ("exit-01", "exit-02")]
        with patch("vps.exit_manager.probe_health_reference", return_value={"ok": False, "error": "reference DNS timeout"}, create=True) as reference:
            for sid in ("exit-01", "exit-02"):
                slot = self.store.get_slot(sid)
                self.assertFalse(self.manager._handle_probe_failure(sid, slot.generation, "tunnel 204 failed"))
        self.assertEqual(1, reference.call_count)
        for sid, runtime in zip(("exit-01", "exit-02"), runtimes):
            slot = self.store.get_slot(sid)
            self.assertEqual("degraded", slot.state)
            self.assertIn("reference DNS timeout", slot.last_error)
            self.assertTrue(runtime.listener.is_ready())
            self.assertFalse(runtime.process.terminated)
            self.assertFalse(runtime.stop.is_set())
            self.assertEqual(0, slot.failure_streak)

    def test_parallel_failed_slots_share_one_reference_request(self):
        for sid in self.manager.managed_slot_ids:
            self.ready_slot(sid)
        def failed_reference(_run):
            time.sleep(0.02)
            return {"ok": False, "error": "reference timed out"}
        def fail(sid):
            slot = self.store.get_slot(sid)
            self.manager._handle_probe_failure(sid, slot.generation, "probe failed")
        with patch("vps.exit_manager.probe_health_reference", side_effect=failed_reference, create=True) as reference:
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                list(pool.map(fail, self.manager.managed_slot_ids))
        self.assertEqual(1, reference.call_count)

    def test_healthy_reference_still_recovers_individually_failed_slot(self):
        runtime = self.ready_slot()
        slot = self.store.get_slot("exit-01")
        with patch("vps.exit_manager.probe_health_reference", return_value={"ok": True}, create=True):
            self.assertTrue(self.manager._handle_probe_failure(slot.id, slot.generation, "tunnel 204 failed"))
        self.assertEqual("failed", self.store.get_slot(slot.id).state)
        self.assertTrue(runtime.process is None or runtime.process.terminated)

    def test_confirmed_dead_path_does_not_prefer_the_same_peer_again(self):
        runtime = self.ready_slot()
        slot = self.store.get_slot("exit-01")
        with patch("vps.exit_manager.probe_health_reference", return_value={"ok": True}, create=True):
            self.assertTrue(self.manager._handle_probe_failure(slot.id, slot.generation, "SOCKS and TUN transport failed"))
        # The failed peer goes through penalty/cooldown instead of a forced retry.
        self.assertEqual("", runtime.preferred_node_ip)

    def test_degraded_slot_returns_ready_only_after_real_socks_probe(self):
        runtime = self.ready_slot()
        slot = self.store.set_runtime("exit-01", state="degraded", last_error="reference unavailable")
        self.manager.routing.is_installed = Mock(return_value=True)
        self.manager._run = Mock(return_value=Mock(returncode=0, stdout="204"))
        with patch.object(runtime.stop, "wait", side_effect=[False, True]):
            self.manager._health_loop(slot.id, slot.generation)
        self.assertEqual("ready", self.store.get_slot(slot.id).state)
        self.assertEqual("", self.store.get_slot(slot.id).last_error)
        self.assertTrue(any("socks5h://" in argument for call in self.manager._run.call_args_list for argument in call.args[0]))

    def test_degraded_slot_stays_degraded_when_socks_probe_still_fails(self):
        runtime = self.ready_slot()
        slot = self.store.set_runtime("exit-01", state="degraded", last_error="reference unavailable")
        self.manager.routing.is_installed = Mock(return_value=True)
        self.manager._run = Mock(return_value=Mock(returncode=28, stdout="000", stderr="SOCKS request timed out"))
        self.manager._sleep = Mock()
        with patch.object(runtime.stop, "wait", side_effect=[False, True]), patch("vps.exit_manager.probe_health_reference", return_value={"ok": False, "error": "reference timed out"}, create=True):
            self.manager._health_loop(slot.id, slot.generation)
        self.assertEqual("degraded", self.store.get_slot(slot.id).state)
        self.assertTrue(runtime.listener.is_ready())

    def test_start_and_enable_do_not_duplicate_live_degraded_worker(self):
        runtime = self.ready_slot()
        slot = self.store.set_runtime("exit-01", state="degraded", last_error="reference unavailable")
        self.manager.start_slot(slot.id)
        self.manager.enable_slot(slot.id)
        self.assertEqual(slot.generation, self.store.get_slot(slot.id).generation)
        self.assertEqual("degraded", self.store.get_slot(slot.id).state)
        self.assertTrue(runtime.listener.is_ready())
        runtime.worker.join.assert_not_called()

    def test_actual_process_exit_is_not_hidden_by_shared_probe_failure(self):
        runtime = self.ready_slot()
        slot = self.store.set_runtime("exit-01", state="degraded", last_error="reference unavailable")
        runtime.process.poll = lambda: 1
        with patch.object(runtime.stop, "wait", side_effect=[False]), patch("vps.exit_manager.probe_health_reference", create=True) as reference:
            self.manager._health_loop(slot.id, slot.generation)
        self.assertEqual("failed", self.store.get_slot(slot.id).state)
        reference.assert_not_called()
        self.assertIn("1", self.store.get_slot(slot.id).last_error)

    def test_last_successful_node_gets_one_preferred_retry(self):
        runtime = self.ready_slot()
        slot = self.store.get_slot("exit-01")
        failed = self.manager._handle_connection_failure(slot.id, slot.generation, "process exited", slot.entry_ip)
        self.assertEqual(slot.entry_ip, runtime.preferred_node_ip)
        # _connect_worker consumes the preferred address when the retry starts.
        runtime.preferred_node_ip = ""
        self.manager._handle_connection_failure(slot.id, failed.generation, "initialization failed", slot.entry_ip)
        self.assertEqual("", runtime.preferred_node_ip)

    def test_initialize_remembers_live_nodes_before_clearing_runtime(self):
        self.ready_slot()
        self.manager.refresh_nodes = Mock(return_value=0)
        self.manager.start_slot = Mock()
        self.manager.initialize()
        self.assertEqual("198.51.100.1", self.manager.runtime("exit-01").preferred_node_ip)

    def test_restart_recovers_last_successful_peer_after_normal_shutdown(self):
        self.ready_slot()
        self.manager.shutdown()
        self.assertEqual("", self.store.get_slot("exit-01").entry_ip)
        restarted = ExitManager(
            self.store, routing=FakeRouting(), listener_factory=FakeListener,
            workspace=self.workspace, start_workers=False,
        )
        restarted.refresh_nodes = Mock(return_value=0)
        restarted.start_slot = Mock()
        restarted.initialize()
        self.assertEqual("198.51.100.1", restarted.runtime("exit-01").preferred_node_ip)
        self.assertEqual("", self.store.last_connected_entry_ip("exit-02"))

    def test_runtime_log_keeps_previous_attempt(self):
        path = self.workspace / "exit-01.log"
        path.write_text("previous failure context", encoding="utf-8")
        self.manager._prepare_runtime_log(path)
        self.assertEqual("previous failure context", path.with_suffix(".log.previous").read_text(encoding="utf-8"))
        self.assertEqual("", path.read_text(encoding="utf-8"))
        self.assertEqual(0o600, path.with_suffix(".log.previous").stat().st_mode & 0o777)


class NodePoolStabilityTest(unittest.TestCase):
    def test_recent_online_node_beats_stale_low_ping_node(self):
        now = time.time()
        pool = NodePool()
        pool.replace([
            {"ip": "198.51.100.1", "country": "JP", "ping": 1, "score": 100, "harvested_at": now - 86400 * 10},
            {"ip": "198.51.100.2", "country": "JP", "ping": 200, "score": 50, "harvested_at": now},
        ])
        self.assertEqual("198.51.100.2", pool.select("JP", set())["ip"])
        self.assertEqual("198.51.100.2", pool.list_nodes("JP")[0]["ip"])

    def test_repeated_recent_failures_do_not_starve_untried_history(self):
        now = time.time()
        pool = NodePool()
        pool.replace([
            {"ip": "198.51.100.1", "country": "US", "ping": 1, "score": 100, "harvested_at": now},
            {"ip": "198.51.100.2", "country": "US", "ping": 20, "score": 50, "harvested_at": now - 86400 * 10},
        ])
        with patch("vps.vpngate.time.monotonic", return_value=1000):
            pool.penalize("198.51.100.1", 10000)
            pool.penalize("198.51.100.1", 10000)
        with patch("vps.vpngate.time.monotonic", return_value=1121):
            self.assertEqual("198.51.100.2", pool.select("US", set())["ip"])

    def test_failed_node_is_cooled_down_then_can_be_retried(self):
        now = time.time()
        pool = NodePool()
        pool.replace([
            {"ip": "198.51.100.1", "country": "JP", "ping": 1, "score": 100, "harvested_at": now},
        ])
        with patch("vps.vpngate.time.monotonic", return_value=1000):
            pool.penalize("198.51.100.1", 10000)
            self.assertIsNone(pool.select("JP", set()))
            pool.replace(pool.list_nodes("JP"))
            self.assertIsNone(pool.select("JP", set()))
        with patch("vps.vpngate.time.monotonic", return_value=1121):
            self.assertEqual("198.51.100.1", pool.select("JP", set())["ip"])
            self.assertIsNone(pool.select("US", set()))


class ReferenceProbeTest(unittest.TestCase):
    def test_reference_is_bounded_direct_diagnostic_not_another_proxy(self):
        run = Mock(return_value=Mock(returncode=0, stdout="204", stderr=""))
        self.assertTrue(probe_health_reference(run)["ok"])
        command = run.call_args.args[0]
        self.assertEqual(7, run.call_args.kwargs["timeout"])
        self.assertEqual("5", command[command.index("--max-time") + 1])
        self.assertEqual("*", command[command.index("--noproxy") + 1])
        self.assertNotIn("-x", command)
        self.assertNotIn("--interface", command)
        self.assertIn("--doh-url", command)

    def test_reference_error_response_is_not_success(self):
        run = Mock(return_value=Mock(returncode=0, stdout="403", stderr=""))
        result = probe_health_reference(run)
        self.assertFalse(result["ok"])
        self.assertEqual("403", result["code"])


if __name__ == "__main__":
    unittest.main()
