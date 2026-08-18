import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from vps.exit_manager import ExitManager
from vps.store import LocalStore


class FakeRouting:
    def __init__(self):
        self.cleaned = []

    def cleanup(self, slot):
        self.cleaned.append(slot.id)


class FakeListener:
    def __init__(self, slot_id, host, port, interface, mark):
        self.slot_id = slot_id
        self.host = host
        self.port = port
        self.interface = interface
        self.mark = mark
        self.started = False
        self.stopped = False

    def start(self, timeout=3):
        self.started = True
        self.stopped = False

    def stop(self):
        self.stopped = True
        self.started = False

    def is_ready(self):
        return self.started and not self.stopped


class FakeProcess:
    def __init__(self):
        self.terminated = False

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return 0


class ExitManagerTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = LocalStore(Path(self.tempdir.name) / "state.db")
        self.store.initialize()
        self.routing = FakeRouting()
        self.manager = ExitManager(
            self.store,
            routing=self.routing,
            listener_factory=FakeListener,
            workspace=Path(self.tempdir.name),
            start_workers=False,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_runtime_profile_only_manages_requested_slots(self):
        manager = ExitManager(
            self.store,
            routing=self.routing,
            listener_factory=FakeListener,
            workspace=Path(self.tempdir.name),
            start_workers=False,
            slot_count=2,
            dial_workers=1,
        )

        self.assertEqual(("exit-01", "exit-02"), manager.managed_slot_ids)
        self.assertEqual(["exit-01", "exit-02"], [slot["id"] for slot in manager.snapshot()])
        with self.assertRaisesRegex(KeyError, "outside the active runtime profile"):
            manager.start_slot("exit-03")

    def test_initialize_cleans_legacy_slots_but_starts_only_managed_slots(self):
        self.store.set_runtime("exit-03", state="ready", entry_ip="198.51.100.3")
        manager = ExitManager(
            self.store,
            routing=self.routing,
            listener_factory=FakeListener,
            workspace=Path(self.tempdir.name),
            start_workers=False,
            slot_count=2,
        )
        started = []
        manager.start_slot = lambda slot_id: started.append(slot_id)
        manager.refresh_nodes = lambda: 0

        manager.initialize()

        self.assertEqual(["exit-01", "exit-02"], started)
        self.assertEqual("idle", self.store.get_slot("exit-03").state)
        self.assertIn("exit-03", self.routing.cleaned)

    def test_dial_semaphore_releases_before_long_running_health_loop(self):
        manager = ExitManager(
            self.store,
            routing=self.routing,
            listener_factory=FakeListener,
            workspace=Path(self.tempdir.name),
            start_workers=False,
            slot_count=2,
            dial_workers=1,
        )
        acquired = []
        released = []

        class TrackingSemaphore:
            def acquire(self, timeout):
                acquired.append(timeout)
                return True

            def release(self):
                released.append(True)

        manager._dial_slots = TrackingSemaphore()
        manager._health_loop = lambda *_args: None
        manager._connect_worker = manager._connect_worker
        manager.node_pool.replace(
            [{"ip": "198.51.100.1", "country": "JP", "ping": 1, "score": 100, "config": ""}]
        )
        manager.config_dir.mkdir(parents=True, exist_ok=True)
        manager.auth_file.write_text("vpn\nvpn\n", encoding="utf-8")
        log_path = manager.workspace / "exit-01.log"

        class InitializedProcess:
            def poll(self): return None
            def terminate(self): pass
            def wait(self, timeout=None): return 0

        def populate_log(*_args, **_kwargs):
            log_path.write_text("Initialization Sequence Completed", encoding="utf-8")
            return InitializedProcess()

        manager._popen = populate_log
        manager.routing.install = lambda *_args: None
        with patch.object(manager, "_default_route", return_value=("172.18.0.1", "eth0")), patch.object(
            manager, "_openvpn_command", return_value=["openvpn"]
        ), patch("vps.exit_manager.detect_egress", return_value="203.0.113.1"), patch(
            "vps.exit_manager.check_residential", return_value=(True, {"status": "checked", "egress_type": "residential"})
        ), patch("vps.exit_manager.probe_targets", return_value={"accepted": True}):
            manager._connect_worker("exit-01", self.store.get_slot("exit-01").generation)

        self.assertEqual([1], acquired)
        self.assertEqual([True], released)

    def test_starting_one_slot_does_not_expose_proxy_before_tunnel_is_ready(self):
        self.manager.start_slot("exit-01")

        runtime = self.manager.runtime("exit-01")
        self.assertIsNone(runtime.listener)
        self.assertIsNone(self.manager.runtime("exit-02").listener)
        self.assertEqual("connecting", self.store.get_slot("exit-01").state)
        self.assertEqual("idle", self.store.get_slot("exit-02").state)

    def test_enabling_already_connecting_slot_is_idempotent(self):
        self.manager.start_slot("exit-01")
        before = self.store.get_slot("exit-01")

        result = self.manager.enable_slot("exit-01")

        self.assertEqual(before.generation, result.generation)
        self.assertEqual("connecting", result.state)

    def test_openvpn_uses_explicit_socks_proxy_for_tunnel_handshake(self):
        with patch.dict(
            os.environ,
            {"KUI_OPENVPN_SOCKS_PROXY": "socks5://host.docker.internal:7896"},
            clear=False,
        ):
            proxy_args = self.manager._openvpn_proxy_args()

        self.assertEqual(["--socks-proxy", "host.docker.internal", "7896"], proxy_args)

    def test_openvpn_socks_proxy_supports_authenticated_upstream(self):
        # aimili-vpngate 支持带认证的上游代理（auth 文件两行 user/pass），当前项目需对齐
        with patch.dict(
            os.environ,
            {"KUI_OPENVPN_SOCKS_PROXY": "socks5://user1:pass1@host.docker.internal:7896"},
            clear=False,
        ):
            proxy_args = self.manager._openvpn_proxy_args()

        self.assertEqual(
            ["--socks-proxy", "host.docker.internal", "7896", str(self.manager.workspace / "socks_auth.txt")],
            proxy_args,
        )
        auth = (self.manager.workspace / "socks_auth.txt").read_text(encoding="utf-8")
        self.assertEqual("user1\npass1\n", auth)

    def test_socks_proxy_node_selection_skips_udp_profiles(self):
        self.manager.node_pool.replace(
            [
                {"ip": "198.51.100.1", "country": "JP", "ping": 1, "score": 100, "config": "proto udp\n"},
                {"ip": "198.51.100.2", "country": "JP", "ping": 2, "score": 90, "config": "proto tcp\n"},
            ]
        )
        with patch.dict(
            os.environ,
            {"KUI_OPENVPN_SOCKS_PROXY": "socks5://host.docker.internal:7896"},
            clear=False,
        ):
            selected = self.manager._select_node("JP", set())

        self.assertEqual("198.51.100.2", selected["ip"])

    def test_refresh_nodes_persists_snapshot_for_restart_fallback(self):
        nodes = [
            {
                "ip": "198.51.100.1",
                "country": "JP",
                "ping": 1,
                "score": 100,
                "config": "proto tcp\n",
                "harvested_at": 1.0,
            }
        ]
        with patch("vps.exit_manager.fetch_all_openvpn_nodes", return_value=(nodes, {"providers": {"vpngate": {"count": 1}}})):
            self.assertEqual(1, self.manager.refresh_nodes())

        persisted = self.store.load_vpn_nodes()
        self.assertEqual("198.51.100.1", persisted[0]["ip"])
        self.assertEqual("vpngate", persisted[0]["source"])

    def test_empty_refresh_loads_cached_snapshot(self):
        nodes = [
            {
                "ip": "198.51.100.1",
                "country": "JP",
                "ping": 1,
                "score": 100,
                "config": "proto tcp\n",
                "harvested_at": 1.0,
            }
        ]
        self.store.replace_vpn_nodes(nodes)
        with patch("vps.exit_manager.fetch_all_openvpn_nodes", return_value=([], {"providers": {}})):
            self.assertEqual(1, self.manager.refresh_nodes())

        self.assertEqual("198.51.100.1", self.manager.node_pool.select("JP", set())["ip"])

    def test_auto_recovery_only_enables_slots_with_distinct_eligible_nodes(self):
        for slot_id in ("exit-01", "exit-02", "exit-03"):
            for attempt in range(3):
                self.manager.fail_slot(slot_id, f"failed {attempt}")
        self.manager.node_pool.replace(
            [
                {"ip": "198.51.100.1", "country": "JP", "ping": 1, "score": 100, "config": "proto tcp\n"},
                {"ip": "198.51.100.2", "country": "JP", "ping": 2, "score": 90, "config": "proto tcp\n"},
            ]
        )
        started = []
        self.manager.start_slot = lambda slot_id: started.append(slot_id)

        self.manager._try_recover_auto_disabled_slots()

        self.assertEqual(["exit-01", "exit-02"], started)
        self.assertTrue(self.store.get_slot("exit-01").enabled)
        self.assertTrue(self.store.get_slot("exit-02").enabled)
        self.assertFalse(self.store.get_slot("exit-03").enabled)

    def test_country_slot_prefers_target_country_over_better_any_candidate(self):
        self.manager.node_pool.replace(
            [
                {"ip": "198.51.100.1", "country": "JP", "ping": 1, "score": 100, "config": "proto tcp\n"},
                {"ip": "198.51.100.2", "country": "US", "ping": 50, "score": 90, "config": "proto tcp\n"},
            ]
        )

        selected = self.manager._reserve_node("exit-01", "US")

        self.assertEqual("US", selected["country"])
        self.assertNotIn("country_fallback", selected)

    def test_country_slot_falls_back_when_target_pool_is_empty(self):
        self.manager.node_pool.replace(
            [{"ip": "198.51.100.1", "country": "JP", "ping": 1, "score": 100, "config": "proto tcp\n"}]
        )

        selected = self.manager._reserve_node("exit-01", "US")

        self.assertEqual("JP", selected["country"])
        self.assertTrue(selected["country_fallback"])
        self.assertEqual("US", selected["target_country"])

    def test_country_slot_uses_non_target_fallback_after_target_failures(self):
        self.manager.node_pool.replace(
            [
                {"ip": "198.51.100.1", "country": "US", "ping": 1, "score": 100, "config": "proto tcp\n"},
                {"ip": "198.51.100.2", "country": "JP", "ping": 2, "score": 90, "config": "proto tcp\n"},
            ]
        )

        selected = self.manager._reserve_node(
            "exit-01",
            "US",
            allow_country_fallback=True,
        )

        self.assertEqual("JP", selected["country"])
        self.assertTrue(selected["country_fallback"])
        self.assertEqual("US", selected["target_country"])

    def test_commit_ready_allows_only_marked_country_fallback(self):
        self.store.update_slot("exit-01", country="US")
        generation = self.store.get_slot("exit-01").generation

        rejected = self.manager.commit_ready(
            "exit-01",
            generation,
            entry_ip="198.51.100.1",
            egress_ip="203.0.113.1",
            node={"country": "JP"},
            check_result={"is_residential": True},
        )
        accepted = self.manager.commit_ready(
            "exit-01",
            generation,
            entry_ip="198.51.100.2",
            egress_ip="203.0.113.2",
            node={"country": "JP", "country_fallback": True, "target_country": "US"},
            check_result={"is_residential": True},
        )

        self.assertFalse(rejected)
        self.assertTrue(accepted)
        slot = self.store.get_slot("exit-01")
        self.assertEqual("US", slot.country)
        self.assertTrue(slot.current_node["country_fallback"])

    def test_country_fallback_starts_only_after_two_target_failures(self):
        slot = self.store.get_slot("exit-01")
        self.assertFalse(self.manager._country_fallback_allowed(slot))
        self.store.set_runtime("exit-01", failure_streak=1)
        self.assertFalse(self.manager._country_fallback_allowed(self.store.get_slot("exit-01")))
        self.store.set_runtime("exit-01", failure_streak=2)
        self.assertTrue(self.manager._country_fallback_allowed(self.store.get_slot("exit-01")))

    def test_country_connection_failure_limit_leaves_three_fallback_attempts(self):
        self.manager.start_workers = False
        for attempt in range(1, 6):
            current = self.store.get_slot("exit-01")
            failed = self.manager._handle_connection_failure(
                "exit-01",
                current.generation,
                f"failed {attempt}",
            )
            self.assertEqual(attempt, failed.failure_streak)
            self.assertEqual(attempt < 5, failed.enabled)

        self.assertEqual("automatic_failure_limit", failed.disabled_reason)

    def test_concurrent_selection_reserves_distinct_nodes_until_released(self):
        self.manager.node_pool.replace(
            [
                {"ip": "198.51.100.1", "country": "JP", "ping": 1, "score": 100, "config": "proto tcp\n"},
                {"ip": "198.51.100.2", "country": "JP", "ping": 2, "score": 90, "config": "proto tcp\n"},
            ]
        )
        with patch.dict(os.environ, {"KUI_OPENVPN_SOCKS_PROXY": ""}, clear=False):
            first = self.manager._reserve_node("exit-01", "JP")
            second = self.manager._reserve_node("exit-02", "JP")

        self.assertEqual("198.51.100.1", first["ip"])
        self.assertEqual("198.51.100.2", second["ip"])
        self.assertEqual({"198.51.100.1", "198.51.100.2"}, self.manager.reserved_entry_ips())

        self.manager._release_node("exit-01")
        self.assertEqual({"198.51.100.2"}, self.manager.reserved_entry_ips())

    def test_enabling_disabled_slot_resets_failure_streak(self):
        for attempt in range(3):
            self.manager.fail_slot("exit-01", f"failed {attempt}")
        self.assertFalse(self.store.get_slot("exit-01").enabled)

        enabled = self.manager.enable_slot("exit-01")

        self.assertTrue(enabled.enabled)
        self.assertEqual(0, enabled.failure_streak)
        self.assertEqual("connecting", enabled.state)

    def test_redial_stops_only_requested_slot_and_increments_generation(self):
        self.manager.start_slot("exit-01")
        self.manager.start_slot("exit-02")
        first = self.manager.runtime("exit-01")
        second = self.manager.runtime("exit-02")
        first.process = FakeProcess()
        second.process = FakeProcess()
        generation = self.store.get_slot("exit-01").generation

        self.manager.redial_slot("exit-01")

        self.assertTrue(first.process is None)
        self.assertFalse(second.process.terminated)
        self.assertGreater(self.store.get_slot("exit-01").generation, generation)
        self.assertEqual(["exit-01"], self.routing.cleaned)

    def test_stop_invalidates_generation_and_restart_clears_the_stop_event(self):
        generation = self.store.get_slot("exit-01").generation

        self.manager.stop_slot("exit-01")
        stopped = self.store.get_slot("exit-01")
        self.assertGreater(stopped.generation, generation)
        self.assertEqual("idle", stopped.state)
        self.assertTrue(self.manager.runtime("exit-01").stop.is_set())

        self.manager.start_slot("exit-01")

        self.assertFalse(self.manager.runtime("exit-01").stop.is_set())
        self.assertFalse(
            self.manager.commit_ready(
                "exit-01",
                generation,
                entry_ip="198.51.100.1",
                egress_ip="203.0.113.1",
                node={"country": "JP"},
                check_result={"is_residential": True},
            )
        )

    def test_commit_ready_starts_listener_only_after_route_and_checks_succeed(self):
        generation = self.store.get_slot("exit-01").generation

        committed = self.manager.commit_ready(
            "exit-01",
            generation,
            entry_ip="198.51.100.1",
            egress_ip="203.0.113.1",
            node={"country": "JP"},
            check_result={"is_residential": True},
        )

        self.assertTrue(committed)
        self.assertTrue(self.manager.runtime("exit-01").listener.started)
        self.assertEqual("ready", self.store.get_slot("exit-01").state)

    def test_commit_ready_persists_full_check_result_before_publication(self):
        generation = self.store.get_slot("exit-01").generation
        check_result = {
            "residential": {"ip_type": "Residential", "raw": {"risk": "low"}},
            "targets": {
                "accepted": True,
                "attempts": [
                    {
                        "url": "https://chatgpt.com",
                        "code": 403,
                        "accepted": True,
                        "classification": "explicit_response",
                        "error": "",
                    }
                ],
            },
        }

        committed = self.manager.commit_ready(
            "exit-01",
            generation,
            entry_ip="198.51.100.1",
            egress_ip="203.0.113.1",
            node={"country": "JP"},
            check_result=check_result,
        )

        self.assertTrue(committed)
        history = self.store.list_check_results(slot_id="exit-01", limit=10)
        self.assertEqual(1, len(history))
        self.assertEqual(generation, history[0]["generation"])
        self.assertEqual(check_result, history[0]["result"])

    def test_stale_generation_cannot_commit_ready_state(self):
        generation = self.store.get_slot("exit-01").generation
        self.store.update_slot("exit-01", country="CA")

        committed = self.manager.commit_ready(
            "exit-01",
            generation,
            entry_ip="198.51.100.1",
            egress_ip="203.0.113.1",
            node={"country": "JP"},
            check_result={"is_residential": True},
        )

        self.assertFalse(committed)
        self.assertNotEqual("ready", self.store.get_slot("exit-01").state)

    def test_commit_ready_rejects_listener_bind_failure(self):
        class FailingListener(FakeListener):
            def start(self, timeout=3):
                raise OSError("address in use")

        manager = ExitManager(
            self.store,
            routing=self.routing,
            listener_factory=FailingListener,
            workspace=Path(self.tempdir.name),
            start_workers=False,
        )
        generation = self.store.get_slot("exit-01").generation

        with self.assertRaisesRegex(OSError, "address in use"):
            manager.commit_ready(
                "exit-01",
                generation,
                entry_ip="198.51.100.1",
                egress_ip="203.0.113.1",
                node={"country": "JP"},
                check_result={"accepted": True},
            )

        self.assertNotEqual("ready", self.store.get_slot("exit-01").state)
        self.assertIsNone(manager.runtime("exit-01").listener)

    def test_failure_racing_commit_cannot_restore_ready(self):
        started = threading.Event()
        release = threading.Event()

        class BlockingListener(FakeListener):
            def start(self, timeout=3):
                started.set()
                release.wait(timeout)
                self.started = True

        manager = ExitManager(
            self.store,
            routing=self.routing,
            listener_factory=BlockingListener,
            workspace=Path(self.tempdir.name),
            start_workers=False,
        )
        generation = self.store.get_slot("exit-01").generation
        result = []
        thread = threading.Thread(
            target=lambda: result.append(
                manager.commit_ready(
                    "exit-01",
                    generation,
                    entry_ip="198.51.100.1",
                    egress_ip="203.0.113.1",
                    node={"country": "JP"},
                    check_result={"accepted": True},
                )
            )
        )
        thread.start()
        self.assertTrue(started.wait(1))

        manager.fail_slot("exit-01", "tunnel lost")
        release.set()
        thread.join(1)

        self.assertEqual([False], result)
        self.assertEqual("failed", self.store.get_slot("exit-01").state)
        self.assertIsNone(manager.runtime("exit-01").listener)

    def test_manual_preferred_udp_node_is_rejected_with_socks_proxy(self):
        self.manager.node_pool.replace(
            [
                {"ip": "198.51.100.1", "country": "JP", "ping": 1, "score": 100, "config": "proto udp\n"},
                {"ip": "198.51.100.2", "country": "JP", "ping": 2, "score": 90, "config": "proto tcp\n"},
            ]
        )
        with patch.dict(
            os.environ,
            {"KUI_OPENVPN_SOCKS_PROXY": "socks5://host.docker.internal:7896"},
            clear=False,
        ):
            selected = self.manager._reserve_node("exit-01", "JP", "198.51.100.1")

        self.assertEqual("198.51.100.2", selected["ip"])

    def test_listener_ready_reflects_live_listener(self):
        generation = self.store.get_slot("exit-01").generation
        self.manager.commit_ready(
            "exit-01",
            generation,
            entry_ip="198.51.100.1",
            egress_ip="203.0.113.1",
            node={"country": "JP"},
            check_result={"accepted": True},
        )

        self.assertTrue(self.manager.listener_ready("exit-01"))
        self.manager.runtime("exit-01").listener.stopped = True
        self.manager.runtime("exit-01").listener.started = False
        self.assertFalse(self.manager.listener_ready("exit-01"))

    def test_failed_target_probe_is_recorded_before_slot_failure(self):
        generation = self.store.get_slot("exit-01").generation
        probe_result = {
            "base_ok": True,
            "custom_ok": False,
            "accepted": False,
            "attempts": [{"url": "https://www.google.com/", "code": "000", "accepted": False}],
        }

        self.manager.record_failed_check(
            "exit-01",
            generation,
            {"residential": {"is_residential": True}, "targets": probe_result},
        )

        history = self.store.list_check_results(slot_id="exit-01", limit=10)
        self.assertEqual(1, len(history))
        self.assertEqual(probe_result, history[0]["result"]["targets"])

    def test_empty_egress_probe_fails_without_endpoint_fallback(self):
        class InitializedProcess:
            def poll(self):
                return None

            def terminate(self):
                return None

            def wait(self, timeout=None):
                return 0

        class PopenFactory:
            def __call__(self, *_args, **_kwargs):
                return InitializedProcess()

        class InstalledRouting(FakeRouting):
            def install(self, *_args):
                return None

        manager = ExitManager(
            self.store,
            routing=InstalledRouting(),
            listener_factory=FakeListener,
            workspace=Path(self.tempdir.name),
            start_workers=False,
            popen=PopenFactory(),
            sleep=lambda *_args: None,
        )
        manager.node_pool.replace(
            [{"ip": "198.51.100.1", "country": "JP", "ping": 1, "score": 100, "config": "proto tcp\n"}]
        )
        manager.config_dir.mkdir(parents=True, exist_ok=True)
        manager.auth_file.write_text("vpn\nvpn\n", encoding="utf-8")
        log_path = manager.workspace / "exit-01.log"
        handled = []
        manager._handle_connection_failure = lambda slot_id, generation, error, endpoint_ip="": handled.append(error)

        def populate_log(*_args, **_kwargs):
            log_path.write_text("Initialization Sequence Completed", encoding="utf-8")
            return InitializedProcess()

        manager._popen = populate_log
        with patch.object(manager, "_default_route", return_value=("172.18.0.1", "eth0")), patch.object(
            manager,
            "_openvpn_command",
            return_value=["openvpn"],
        ), patch(
            "vps.exit_manager.detect_egress",
            return_value="",
        ), patch("vps.exit_manager.check_residential") as residential:
            manager._connect_worker("exit-01", self.store.get_slot("exit-01").generation)

        self.assertIn("real egress IP unavailable", handled)
        residential.assert_not_called()

    def test_connection_failure_defers_retry_and_keeps_failed_state(self):
        generation = self.store.get_slot("exit-01").generation
        scheduled = []
        self.manager.start_workers = True
        self.manager._schedule_retry = lambda slot_id, failed_generation, delay: scheduled.append(
            (slot_id, failed_generation, delay)
        )

        self.manager._handle_connection_failure(
            "exit-01",
            generation,
            "OpenVPN initialization failed",
            "198.51.100.1",
        )

        failed = self.store.get_slot("exit-01")
        self.assertEqual("failed", failed.state)
        self.assertEqual("OpenVPN initialization failed", failed.last_error)
        self.assertEqual([("exit-01", failed.generation, 5)], scheduled)

    def test_connection_failure_penalizes_failed_node_before_retry(self):
        self.manager.node_pool.replace(
            [
                {"ip": "198.51.100.1", "country": "JP", "ping": 1, "score": 100, "config": ""},
                {"ip": "198.51.100.2", "country": "JP", "ping": 2, "score": 90, "config": ""},
            ]
        )
        generation = self.store.get_slot("exit-01").generation

        self.manager._handle_connection_failure(
            "exit-01",
            generation,
            "OpenVPN initialization failed",
            "198.51.100.1",
        )

        selected = self.manager.node_pool.select("JP", set())
        self.assertEqual("198.51.100.2", selected["ip"])

    def test_retry_callback_restarts_only_unchanged_failed_slot(self):
        failed = self.manager.fail_slot("exit-01", "OpenVPN initialization failed")
        restarted = []
        self.manager.start_slot = lambda slot_id: restarted.append(slot_id)

        self.manager._retry_failed_slot("exit-01", failed.generation)
        self.store.update_slot("exit-01", country="CA")
        self.manager._retry_failed_slot("exit-01", failed.generation)

        self.assertEqual(["exit-01"], restarted)

    def test_failed_ready_slot_stops_listener_before_retry(self):
        generation = self.store.get_slot("exit-01").generation
        self.manager.commit_ready(
            "exit-01",
            generation,
            entry_ip="198.51.100.1",
            egress_ip="203.0.113.1",
            node={"country": "JP"},
            check_result={"is_residential": True},
        )
        listener = self.manager.runtime("exit-01").listener

        self.manager.fail_slot("exit-01", "health failed")

        self.assertTrue(listener.stopped)
        self.assertIsNone(self.manager.runtime("exit-01").listener)

    def test_health_loop_fails_ready_slot_when_policy_route_disappears(self):
        generation = self.store.get_slot("exit-01").generation
        self.manager.commit_ready(
            "exit-01",
            generation,
            entry_ip="198.51.100.1",
            egress_ip="203.0.113.1",
            node={"country": "JP"},
            check_result={"is_residential": True},
        )
        runtime = self.manager.runtime("exit-01")
        runtime.process = type("RunningProcess", (), {"poll": lambda self: None})()
        handled = []
        self.manager.routing.is_installed = lambda _slot: False
        self.manager._handle_connection_failure = lambda slot_id, failed_generation, error, endpoint_ip="": handled.append(
            (slot_id, failed_generation, error, endpoint_ip)
        )
        waits = iter([False])
        runtime.stop.wait = lambda _timeout: next(waits, True)
        with patch("vps.exit_manager.probe_204") as probe:
            self.manager._health_loop("exit-01", generation)

        probe.assert_not_called()
        self.assertEqual(
            [("exit-01", generation, "policy route disappeared", "198.51.100.1")],
            handled,
        )

    def test_health_loop_records_failure_and_schedules_retry_after_two_consecutive_204_failures(self):
        generation = self.store.get_slot("exit-01").generation
        self.manager.commit_ready(
            "exit-01",
            generation,
            entry_ip="198.51.100.1",
            egress_ip="203.0.113.1",
            node={"country": "JP"},
            check_result={"is_residential": True},
        )
        runtime = self.manager.runtime("exit-01")
        runtime.process = type("RunningProcess", (), {"poll": lambda self: None})()
        self.manager.routing.is_installed = lambda _slot: True
        self.manager._run = lambda command, capture_output=True, text=True, check=False: type(
            "CmdResult", (), {"returncode": 0, "stdout": "500"}
        )()

        scheduled = []
        self.manager.start_workers = True
        self.manager._schedule_retry = lambda slot_id, failed_generation, delay: scheduled.append(
            (slot_id, failed_generation, delay)
        )
        self.manager.redial_slot = lambda _slot_id: self.fail("health worker must not redial itself")

        waits = iter([False, False])
        runtime.stop.wait = lambda _timeout: next(waits, True)
        self.manager._health_loop("exit-01", generation)

        failed = self.store.get_slot("exit-01")
        self.assertTrue(failed.enabled)
        self.assertEqual("failed", failed.state)
        self.assertEqual(1, failed.failure_streak)
        self.assertEqual("HTTP 204 probe failed twice consecutively", failed.last_error)
        self.assertEqual([("exit-01", failed.generation, 5)], scheduled)
        self.assertTrue(runtime.stop.is_set())

    def test_repeated_health_failures_auto_disable_only_the_failed_slot(self):
        class RunningProcess:
            def poll(self):
                return None

            def terminate(self):
                return None

            def wait(self, timeout=None):
                return 0

        self.manager.routing.is_installed = lambda _slot: True
        self.manager._run = lambda command, capture_output=True, text=True, check=False: type(
            "CmdResult", (), {"returncode": 0, "stdout": "500"}
        )()
        self.manager.start_workers = False

        for attempt in range(5):
            generation = self.store.get_slot("exit-01").generation
            runtime = self.manager.runtime("exit-01")
            runtime.process = RunningProcess()
            waits = iter([False, False])
            runtime.stop.wait = lambda _timeout, waits=waits: next(waits, True)
            self.manager._health_loop("exit-01", generation)
            current = self.store.get_slot("exit-01")
            if current.enabled:
                self.manager.start_slot("exit-01")

        failed = self.store.get_slot("exit-01")
        self.assertFalse(failed.enabled)
        self.assertEqual("disabled", failed.state)
        self.assertEqual(5, failed.failure_streak)
        self.assertEqual("automatic_failure_limit", failed.disabled_reason)
        self.assertTrue(self.store.get_slot("exit-02").enabled)

    def test_health_loop_resets_failures_on_successful_204_probe(self):
        generation = self.store.get_slot("exit-01").generation
        self.manager.commit_ready(
            "exit-01",
            generation,
            entry_ip="198.51.100.1",
            egress_ip="203.0.113.1",
            node={"country": "JP"},
            check_result={"is_residential": True},
        )
        runtime = self.manager.runtime("exit-01")
        runtime.process = type("RunningProcess", (), {"poll": lambda self: None})()
        self.manager.routing.is_installed = lambda _slot: True

        # First run fails, second run succeeds (204).
        probe_responses = iter(["500", "204"])
        self.manager._run = lambda command, capture_output=True, text=True, check=False: type(
            "CmdResult", (), {"returncode": 0, "stdout": next(probe_responses)}
        )()
        self.manager.redial_slot = lambda _slot_id: self.fail("a successful probe must not redial")

        waits = iter([False, False])
        runtime.stop.wait = lambda _timeout: next(waits, True)
        self.manager._health_loop("exit-01", generation)

        self.assertEqual("ready", self.store.get_slot("exit-01").state)
        self.assertEqual(0, self.store.get_slot("exit-01").failure_streak)

    def test_health_loop_returns_immediately_when_slot_stop_event_is_set(self):
        generation = self.store.get_slot("exit-01").generation
        self.manager.commit_ready(
            "exit-01",
            generation,
            entry_ip="198.51.100.1",
            egress_ip="203.0.113.1",
            node={"country": "JP"},
            check_result={"is_residential": True},
        )
        runtime = self.manager.runtime("exit-01")
        runtime.process = type("RunningProcess", (), {"poll": lambda self: None})()
        runtime.stop.set()
        with patch.object(self.manager.routing, "is_installed", create=True) as route_check, patch(
            "vps.exit_manager.probe_204"
        ) as probe:
            self.manager._health_loop("exit-01", generation)

        route_check.assert_not_called()
        probe.assert_not_called()

    def test_third_failure_disables_only_failed_slot(self):
        for attempt in range(3):
            self.manager.fail_slot("exit-01", f"failed {attempt}")

        self.assertFalse(self.store.get_slot("exit-01").enabled)
        self.assertTrue(self.store.get_slot("exit-02").enabled)
        self.assertEqual("disabled", self.store.get_slot("exit-01").state)

    def test_allow_non_residential_allows_datacenter_when_enabled(self):
        generation = self.store.get_slot("exit-01").generation
        datacenter_result = {
            "status": "checked",
            "is_residential": False,
            "egress_type": "datacenter",
            "egress_type_label": "机房IP",
        }
        handled = []
        self.manager._handle_connection_failure = lambda slot_id, gen, err, endpoint_ip="": handled.append(err)

        class InitializedProcess:
            def poll(self): return None
            def terminate(self): pass
            def wait(self, timeout=None): return 0

        self.manager.node_pool.replace([{"ip": "198.51.100.1", "country": "JP", "ping": 1, "score": 100, "config": ""}])
        self.manager.config_dir.mkdir(parents=True, exist_ok=True)
        self.manager.auth_file.write_text("vpn\nvpn\n", encoding="utf-8")
        log_path = self.manager.workspace / "exit-01.log"

        def populate_log(*_args, **_kwargs):
            log_path.write_text("Initialization Sequence Completed", encoding="utf-8")
            return InitializedProcess()

        self.manager._popen = populate_log
        self.manager.routing.install = lambda *_args, **_kwargs: None
        self.manager.routing.is_installed = lambda *_args, **_kwargs: True
        with patch.dict(os.environ, {"KUI_ALLOW_NON_RESIDENTIAL": "1"}), patch.object(
            self.manager, "_default_route", return_value=("172.18.0.1", "eth0")
        ), patch.object(
            self.manager, "_openvpn_command", return_value=["openvpn"]
        ), patch.object(
            self.manager, "_health_loop", return_value=None
        ), patch(
            "vps.exit_manager.detect_egress", return_value="203.0.113.1"
        ), patch(
            "vps.exit_manager.check_residential", return_value=(False, datacenter_result)
        ), patch(
            "vps.exit_manager.probe_targets", return_value={"accepted": True}
        ):
            self.manager._connect_worker("exit-01", generation)

        self.assertEqual("ready", self.store.get_slot("exit-01").state)
        self.assertEqual([], handled)

    def test_unknown_testisp_fails_even_if_allow_non_residential_enabled(self):
        generation = self.store.get_slot("exit-01").generation
        unknown_result = {
            "status": "unknown",
            "is_residential": False,
            "egress_type": "unknown",
            "egress_type_label": "未知IP类型",
        }
        handled = []
        self.manager._handle_connection_failure = lambda slot_id, gen, err, endpoint_ip="": handled.append(err)

        class InitializedProcess:
            def poll(self): return None
            def terminate(self): pass
            def wait(self, timeout=None): return 0

        self.manager.node_pool.replace([{"ip": "198.51.100.1", "country": "JP", "ping": 1, "score": 100, "config": ""}])
        self.manager.config_dir.mkdir(parents=True, exist_ok=True)
        self.manager.auth_file.write_text("vpn\nvpn\n", encoding="utf-8")
        log_path = self.manager.workspace / "exit-01.log"

        def populate_log(*_args, **_kwargs):
            log_path.write_text("Initialization Sequence Completed", encoding="utf-8")
            return InitializedProcess()

        self.manager._popen = populate_log
        self.manager.routing.install = lambda *_args, **_kwargs: None
        with patch.dict(os.environ, {"KUI_ALLOW_NON_RESIDENTIAL": "1"}), patch.object(
            self.manager, "_default_route", return_value=("172.18.0.1", "eth0")
        ), patch.object(
            self.manager, "_openvpn_command", return_value=["openvpn"]
        ), patch(
            "vps.exit_manager.detect_egress", return_value="203.0.113.1"
        ), patch(
            "vps.exit_manager.check_residential", return_value=(False, unknown_result)
        ):
            self.manager._connect_worker("exit-01", generation)

        self.assertEqual(1, len(handled))
        self.assertIn("TestISP check failed", handled[0])


if __name__ == "__main__":
    unittest.main()
