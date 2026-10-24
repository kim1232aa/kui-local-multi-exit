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


class ExitHealthScheduleTest(unittest.TestCase):
    def setUp(self):
        temp_root = Path(__file__).resolve().parents[1] / "temp"
        temp_root.mkdir(exist_ok=True)
        self.tempdir = tempfile.TemporaryDirectory(dir=temp_root)
        self.addCleanup(self.tempdir.cleanup)
        self.store = LocalStore(Path(self.tempdir.name) / "state.db")
        self.store.initialize(slot_count=3)
        self.manager = ExitManager(
            self.store, routing=FakeRouting(), listener_factory=FakeListener,
            workspace=self.tempdir.name, start_workers=False,
        )
        self.manager.routing.is_installed = Mock(return_value=True)
        self.manager._verify_client_path = Mock(return_value=True)

    def ready_slot(self, slot_id="exit-01", age=0):
        slot = self.store.get_slot(slot_id)
        self.manager.commit_ready(
            slot_id, slot.generation, entry_ip="198.51.100.1", egress_ip="203.0.113.1",
            node={"country": "JP"}, check_result={},
        )
        runtime = self.manager.runtime(slot_id)
        runtime.process = FakeProcess()
        runtime.worker = Mock(is_alive=Mock(return_value=True))
        with self.store._lock, self.store._connect() as db:
            db.execute("UPDATE exit_slots SET updated_at = ? WHERE id = ?", (int(time.time()) - age, slot_id))
        return self.store.get_slot(slot_id), runtime

    def test_first_checks_and_subsequent_checks_are_staggered(self):
        first_delays = []
        for index, sid in enumerate(self.manager.managed_slot_ids, 1):
            slot, runtime = self.ready_slot(sid)
            with patch.object(self.manager, "_wait_for_health_check", side_effect=[True, False]) as wait:
                self.manager._health_loop(sid, slot.generation)
            first_delays.append(wait.call_args_list[0].args[3])
            self.assertEqual(300 + index * 10, wait.call_args_list[1].args[3])
            self.assertFalse(runtime.stop.is_set())
        self.assertEqual([100, 200, 300], first_delays)

    def test_each_normal_round_verifies_socks_once_without_diagnosis(self):
        slot, _runtime = self.ready_slot()
        with patch.object(self.manager, "_wait_for_health_check", side_effect=[True, True, False]), patch.object(
            self.manager, "_diagnose_client_failure",
        ) as diagnosis:
            self.manager._health_loop(slot.id, slot.generation)
        self.assertEqual(2, self.manager._verify_client_path.call_count)
        diagnosis.assert_not_called()

    def test_first_failure_rechecks_after_thirty_seconds_then_returns_to_normal(self):
        slot, _runtime = self.ready_slot()
        self.manager._verify_client_path.side_effect = [False, True]
        with patch.object(self.manager, "_wait_for_health_check", side_effect=[True, True, False]) as wait, patch.object(
            self.manager, "_diagnose_client_failure",
        ) as failure:
            self.manager._health_loop(slot.id, slot.generation)
        self.assertEqual([100, 30, 310], [call.args[3] for call in wait.call_args_list])
        failure.assert_not_called()
        self.assertEqual("ready", self.store.get_slot(slot.id).state)

    def test_two_failures_are_confirmed_without_waiting_five_minutes(self):
        slot, _runtime = self.ready_slot()
        self.manager._verify_client_path.return_value = False
        with patch.object(self.manager, "_wait_for_health_check", side_effect=[True, True]) as wait, patch.object(
            self.manager, "_diagnose_client_failure", return_value=True,
        ) as failure:
            self.manager._health_loop(slot.id, slot.generation)
        self.assertEqual([100, 30], [call.args[3] for call in wait.call_args_list])
        failure.assert_called_once_with(slot.id, slot.generation)

    def test_persistent_degraded_path_uses_capped_backoff(self):
        slot, _runtime = self.ready_slot()
        self.store.set_runtime(slot.id, state="degraded")
        self.manager._verify_client_path.return_value = False
        with patch.object(self.manager, "_wait_for_health_check", side_effect=[True] * 5 + [False]) as wait, patch.object(
            self.manager, "_diagnose_client_failure", return_value=False,
        ):
            self.manager._health_loop(slot.id, slot.generation)
        self.assertEqual([30, 30, 60, 120, 300, 300], [call.args[3] for call in wait.call_args_list])
        self.assertEqual("degraded", self.store.get_slot(slot.id).state)

    def test_long_wait_updates_only_worker_liveness_not_success_timestamp(self):
        slot, runtime = self.ready_slot(age=600)
        clock = [1000.0]
        waits = []
        self.manager.redial_slot = Mock()

        def advance(delay):
            waits.append(delay)
            clock[0] += delay
            self.manager._try_recover_stale_slots()
            return False

        with patch("vps.exit_manager.time.monotonic", side_effect=lambda: clock[0]), patch.object(
            runtime.stop, "wait", side_effect=advance,
        ):
            self.assertTrue(self.manager._wait_for_health_check(slot.id, slot.generation, runtime.stop, 300))
        self.assertEqual(20, len(waits))
        self.assertTrue(all(delay == 15 for delay in waits))
        self.assertEqual((slot.generation, 1300), runtime.health_heartbeat)
        self.assertEqual(slot.updated_at, self.store.get_slot(slot.id).updated_at)
        self.manager.redial_slot.assert_not_called()

    def test_real_stalled_worker_heartbeat_still_triggers_recovery(self):
        slot, runtime = self.ready_slot()
        runtime.health_heartbeat = (slot.generation, 1000)
        self.manager.redial_slot = Mock()
        with patch("vps.exit_manager.time.monotonic", return_value=1181):
            self.manager._try_recover_stale_slots()
        self.manager.redial_slot.assert_called_once_with(slot.id, automatic=True)

    def test_old_generation_heartbeat_cannot_hide_expired_current_worker(self):
        slot, runtime = self.ready_slot(age=240)
        runtime.health_heartbeat = (slot.generation - 1, 1000)
        self.manager.redial_slot = Mock()
        with patch("vps.exit_manager.time.monotonic", return_value=1001):
            self.manager._try_recover_stale_slots()
        self.manager.redial_slot.assert_called_once_with(slot.id, automatic=True)

    def test_generation_change_interrupts_wait_and_does_not_refresh_new_worker(self):
        slot, runtime = self.ready_slot()
        clock = [1000.0]

        def change_generation(_delay):
            clock[0] += 15
            self.store.update_slot(slot.id, enabled=False)
            return False

        with patch("vps.exit_manager.time.monotonic", side_effect=lambda: clock[0]), patch.object(
            runtime.stop, "wait", side_effect=change_generation,
        ):
            self.assertFalse(self.manager._wait_for_health_check(slot.id, slot.generation, runtime.stop, 300))
        self.assertEqual((slot.generation, 1000), runtime.health_heartbeat)

    def test_stopping_slot_interrupts_long_wait(self):
        slot, runtime = self.ready_slot()
        with patch.object(runtime.stop, "wait", return_value=True) as wait:
            self.assertFalse(self.manager._wait_for_health_check(slot.id, slot.generation, runtime.stop, 300))
        wait.assert_called_once()
        self.assertLessEqual(wait.call_args.args[0], 15)

    def test_health_checks_are_limited_to_two_simultaneous_slots(self):
        slots = [self.ready_slot(sid)[0] for sid in self.manager.managed_slot_ids]
        release = threading.Event()
        two_active = threading.Event()
        lock = threading.Lock()
        active = 0
        peak = 0
        calls = 0
        waits = {}

        def one_round(sid, _gen, _stop, _delay):
            with lock:
                waits[sid] = waits.get(sid, 0) + 1
                return waits[sid] == 1

        def probe(*_args):
            nonlocal active, peak, calls
            with lock:
                active += 1
                calls += 1
                peak = max(peak, active)
                if active == 2:
                    two_active.set()
            try:
                if not release.wait(2):
                    raise AssertionError("test probe was not released")
                return True
            finally:
                with lock:
                    active -= 1

        with patch.object(self.manager, "_wait_for_health_check", side_effect=one_round), patch.object(
            self.manager, "_verify_client_path", side_effect=probe,
        ), concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            futures = [pool.submit(self.manager._health_loop, slot.id, slot.generation) for slot in slots]
            try:
                self.assertTrue(two_active.wait(1))
                with lock:
                    self.assertEqual(2, calls)
                    self.assertEqual(2, active)
            finally:
                release.set()
            for future in futures:
                future.result(timeout=3)
        self.assertEqual(3, calls)
        self.assertEqual(2, peak)

    def test_exception_releases_health_permit(self):
        slot, _runtime = self.ready_slot()
        with patch.object(self.manager, "_wait_for_health_check", return_value=True), patch.object(
            self.manager, "_verify_client_path", side_effect=RuntimeError("test probe failure"),
        ), self.assertRaisesRegex(RuntimeError, "test probe failure"):
            self.manager._health_loop(slot.id, slot.generation)
        self.assertTrue(self.manager._health_slots.acquire(blocking=False))
        self.assertTrue(self.manager._health_slots.acquire(blocking=False))
        self.assertFalse(self.manager._health_slots.acquire(blocking=False))
        self.manager._health_slots.release()
        self.manager._health_slots.release()

    def test_queue_wait_updates_liveness_and_is_not_a_probe_failure(self):
        slot, runtime = self.ready_slot()
        semaphore = Mock(acquire=Mock(side_effect=[False, True]))
        self.manager._health_slots = semaphore
        with patch("vps.exit_manager.time.monotonic", side_effect=[1000, 1001]):
            self.assertTrue(self.manager._acquire_health_slot(slot.id, slot.generation, runtime.stop))
        self.assertEqual((slot.generation, 1001), runtime.health_heartbeat)
        self.assertEqual("ready", self.store.get_slot(slot.id).state)
        self.assertEqual(0, self.store.get_slot(slot.id).failure_streak)
        semaphore.release.assert_not_called()

    def test_generation_change_after_permit_acquisition_releases_it(self):
        slot, runtime = self.ready_slot()

        def acquire(timeout):
            self.store.update_slot(slot.id, enabled=False)
            return True

        self.manager._health_slots = Mock(acquire=Mock(side_effect=acquire))
        self.assertFalse(self.manager._acquire_health_slot(slot.id, slot.generation, runtime.stop))
        self.manager._health_slots.release.assert_called_once()

    def test_shutdown_interrupts_waiting_for_health_permit(self):
        slot, runtime = self.ready_slot()

        def acquire(timeout):
            self.manager._shutdown.set()
            return False

        self.manager._health_slots = Mock(acquire=Mock(side_effect=acquire))
        self.assertFalse(self.manager._acquire_health_slot(slot.id, slot.generation, runtime.stop))
        self.manager._health_slots.release.assert_not_called()
        self.assertEqual(0, self.store.get_slot(slot.id).failure_streak)

    def test_error_during_permit_validation_releases_it(self):
        slot, runtime = self.ready_slot()
        self.manager._health_slots = Mock(acquire=Mock(return_value=True))
        with patch.object(self.manager, "_worker_is_stale", side_effect=[False, RuntimeError("test store failure")]), self.assertRaisesRegex(
            RuntimeError, "test store failure",
        ):
            self.manager._acquire_health_slot(slot.id, slot.generation, runtime.stop)
        self.manager._health_slots.release.assert_called_once()

    def test_late_probe_does_not_verify_or_mutate_a_new_generation(self):
        slot, runtime = self.ready_slot()

        def late_probe(*_args):
            self.store.update_slot(slot.id, enabled=False)
            return True

        with patch.object(self.manager, "_wait_for_health_check", return_value=True), patch.object(
            self.manager, "_verify_client_path", side_effect=late_probe,
        ) as verify:
            self.manager._health_loop(slot.id, slot.generation)
        verify.assert_called_once()
        self.assertNotIn("health", self.store.get_slot(slot.id).check_result)
        self.assertFalse(self.store.get_slot(slot.id).enabled)
        self.assertTrue(self.manager._health_slots.acquire(blocking=False))
        self.assertTrue(self.manager._health_slots.acquire(blocking=False))
        self.manager._health_slots.release()
        self.manager._health_slots.release()


if __name__ == "__main__":
    unittest.main()
