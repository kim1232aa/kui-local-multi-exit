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

        updated = self.store.update_slot("exit-01", country="CA", proxy_port=9001)

        self.assertEqual("CA", updated.country)
        self.assertEqual(9001, updated.proxy_port)
        self.assertEqual(before, self.store.get_slot("exit-02"))

    def test_rejects_invalid_country_and_duplicate_port(self):
        with self.assertRaisesRegex(ValueError, "country"):
            self.store.update_slot("exit-01", country="JAPAN")

        with self.assertRaisesRegex(ValueError, "already used"):
            self.store.update_slot("exit-01", proxy_port=7921)

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


if __name__ == "__main__":
    unittest.main()
