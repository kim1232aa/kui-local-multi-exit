import contextlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from vps.store import LocalStore


class LocalStoreTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "state.db"
        self.store = LocalStore(self.db_path)
        self.store.initialize()

    def tearDown(self):
        self.tempdir.cleanup()

    def test_initializes_twelve_editable_exit_slots(self):
        slots = self.store.list_slots()

        self.assertEqual(12, len(slots))
        self.assertEqual(
            ["JP", "JP", "US", "US", "GB", "GB", "DE", "DE", "KR", "KR", "SG", "SG"],
            [slot.country for slot in slots],
        )
        self.assertEqual(list(range(7920, 7932)), [slot.proxy_port for slot in slots])
        self.assertEqual([f"tun{i}" for i in range(12)], [slot.tunnel_name for slot in slots])
        self.assertEqual(list(range(200, 212)), [slot.route_table for slot in slots])

    def test_updates_one_slot_without_changing_other_slots(self):
        before = self.store.get_slot("exit-02")

        updated = self.store.update_slot("exit-01", country="CA")

        self.assertEqual("CA", updated.country)
        self.assertEqual(7920, updated.proxy_port)
        self.assertEqual(before, self.store.get_slot("exit-02"))

    def test_rejects_invalid_country_duplicate_and_unpublished_port(self):
        with self.assertRaisesRegex(ValueError, "country"):
            self.store.update_slot("exit-01", country="JAPAN")

        with self.assertRaisesRegex(ValueError, "already used"):
            self.store.update_slot("exit-01", proxy_port=7921)

        with self.assertRaisesRegex(ValueError, "7920 through 7931"):
            self.store.update_slot("exit-01", proxy_port=9001)

    def test_three_consecutive_failures_auto_disable_only_that_slot(self):
        for attempt in range(1, 4):
            slot = self.store.record_failure("exit-01", f"dial failed {attempt}")

        self.assertFalse(slot.enabled)
        self.assertEqual(3, slot.failure_streak)
        self.assertEqual("automatic_failure_limit", slot.disabled_reason)
        self.assertTrue(self.store.get_slot("exit-02").enabled)

    def test_manual_enable_clears_failure_state_and_increments_generation(self):
        for attempt in range(3):
            self.store.record_failure("exit-01", f"failure {attempt}")
        disabled = self.store.get_slot("exit-01")

        enabled = self.store.enable_slot("exit-01")

        self.assertTrue(enabled.enabled)
        self.assertEqual(0, enabled.failure_streak)
        self.assertEqual("", enabled.disabled_reason)
        self.assertGreater(enabled.generation, disabled.generation)

    def test_runtime_state_and_events_are_persisted(self):
        self.store.set_runtime(
            "exit-01",
            state="ready",
            entry_ip="198.51.100.10",
            egress_ip="203.0.113.9",
            current_node={"country": "JP", "ping": 22},
            check_result={"is_residential": True},
        )
        self.store.record_event("exit-01", "connected", "tunnel ready")

        reopened = LocalStore(self.db_path)
        slot = reopened.get_slot("exit-01")
        events = reopened.list_events(limit=10)

        self.assertEqual("ready", slot.state)
        self.assertEqual("203.0.113.9", slot.egress_ip)
        self.assertEqual({"country": "JP", "ping": 22}, slot.current_node)
        self.assertEqual({"is_residential": True}, slot.check_result)
        self.assertEqual("connected", events[0]["kind"])

    def test_validate_slot_update_checks_port_before_runtime_actions(self):
        with self.assertRaisesRegex(ValueError, "7920 through 7931"):
            self.store.validate_slot_update("exit-01", country=None, proxy_port=9001, enabled=None)

    def test_stale_generation_cannot_write_runtime(self):
        current = self.store.get_slot("exit-01")
        self.store.update_slot("exit-01", country="CA")

        updated = self.store.set_runtime_if_generation(
            "exit-01",
            current.generation,
            state="ready",
            egress_ip="203.0.113.9",
        )

        self.assertIsNone(updated)
        self.assertNotEqual("ready", self.store.get_slot("exit-01").state)

    def test_vpngate_snapshot_survives_reopen(self):
        nodes = [
            {
                "ip": "198.51.100.1",
                "country": "JP",
                "ping": 22,
                "score": 100,
                "config": "proto tcp\n",
                "harvested_at": 1.0,
            }
        ]
        self.store.replace_vpn_nodes(nodes)

        reopened = LocalStore(self.db_path)
        reopened.initialize()

        self.assertEqual(nodes, reopened.load_vpn_nodes())

    def test_check_results_are_persisted_and_filterable_by_slot(self):
        self.store.append_check_result(
            "exit-01",
            3,
            {"egress_ip": "203.0.113.9", "accepted": True},
        )
        self.store.append_check_result(
            "exit-02",
            4,
            {"egress_ip": "203.0.113.10", "accepted": False},
        )

        reopened = LocalStore(self.db_path)
        reopened.initialize()
        results = reopened.list_check_results(slot_id="exit-01", limit=10)

        self.assertEqual(1, len(results))
        self.assertEqual("exit-01", results[0]["slot_id"])
        self.assertEqual(3, results[0]["generation"])
        self.assertEqual(
            {"egress_ip": "203.0.113.9", "accepted": True},
            results[0]["result"],
        )
        self.assertGreater(results[0]["created_at"], 0)

    def test_delete_setting_removes_only_requested_value(self):
        self.store.set_setting("probe_server_exit-01", '{"name":"Tokyo"}')
        self.store.set_setting("probe_server_exit-02", '{"name":"Osaka"}')

        self.store.delete_setting("probe_server_exit-01")

        self.assertEqual("", self.store.get_setting("probe_server_exit-01"))
        self.assertEqual('{"name":"Osaka"}', self.store.get_setting("probe_server_exit-02"))

    def test_initialize_migrates_legacy_management_tables_without_losing_rows(self):
        legacy_path = Path(self.tempdir.name) / "legacy.db"
        with contextlib.closing(sqlite3.connect(legacy_path)) as db:
            db.executescript(
                """
                CREATE TABLE vps_list (
                    ip TEXT PRIMARY KEY,
                    name TEXT NOT NULL DEFAULT '',
                    os TEXT NOT NULL DEFAULT 'debian',
                    egress_mode TEXT NOT NULL DEFAULT '',
                    socks5_addr TEXT NOT NULL DEFAULT '',
                    socks5_port INTEGER NOT NULL DEFAULT 0,
                    socks5_user TEXT NOT NULL DEFAULT '',
                    socks5_pass TEXT NOT NULL DEFAULT '',
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE node_list (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    protocol TEXT NOT NULL DEFAULT '',
                    enable INTEGER NOT NULL DEFAULT 1,
                    traffic_used INTEGER NOT NULL DEFAULT 0,
                    traffic_limit INTEGER NOT NULL DEFAULT 0,
                    expire_time INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL
                );
                INSERT INTO vps_list (ip, name, os, created_at)
                VALUES ('10.0.0.41', 'legacy-vps', 'debian', 1);
                INSERT INTO node_list (id, ip, name, protocol, created_at)
                VALUES (41, '10.0.0.41', 'legacy-node', 'VLESS', 1);
                """
            )

        migrated = LocalStore(legacy_path)
        migrated.initialize()

        with contextlib.closing(sqlite3.connect(legacy_path)) as db:
            vps_columns = {row[1] for row in db.execute("PRAGMA table_info(vps_list)")}
            node_columns = {row[1] for row in db.execute("PRAGMA table_info(node_list)")}
        self.assertTrue({
            "proxy_mode", "proxy_categories", "egress_revision", "egress_status",
            "egress_applied_mode", "egress_applied_revision", "egress_error", "egress_ip",
        }.issubset(vps_columns))
        self.assertTrue({
            "address", "port", "username", "uuid", "password", "sni", "private_key",
            "public_key", "short_id", "flow", "network", "host", "path", "extra",
            "relay_type", "target_ip", "target_port", "target_id",
        }.issubset(node_columns))
        self.assertEqual("legacy-vps", migrated.get_vps("10.0.0.41")["name"])
        legacy_node = migrated.get_node(41)
        self.assertEqual("legacy-node", legacy_node["name"])
        self.assertEqual("10.0.0.41", legacy_node["vps_ip"])

    def test_record_failure_clears_current_runtime(self):
        self.store.set_runtime(
            "exit-01",
            state="ready",
            entry_ip="198.51.100.1",
            egress_ip="203.0.113.1",
            current_node={"ip": "198.51.100.1"},
            check_result={"targets": []},
        )

        failed = self.store.record_failure("exit-01", "lost tunnel")

        self.assertEqual("", failed.entry_ip)
        self.assertEqual("", failed.egress_ip)
        self.assertEqual({}, failed.current_node)
        self.assertEqual({}, failed.check_result)


if __name__ == "__main__":
    unittest.main()
