import tempfile
import unittest
from pathlib import Path

from vps.runtime_profile import GIB, resolve_runtime_profile


class RuntimeProfileTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.cgroup_root = self.root / "cgroup"
        self.cgroup_root.mkdir()
        self.meminfo_path = self.root / "meminfo"

    def tearDown(self):
        self.tempdir.cleanup()

    def _write_meminfo(self, kib: int) -> None:
        self.meminfo_path.write_text(f"MemTotal:       {kib} kB\n", encoding="utf-8")

    def test_cgroup_v2_limit_has_priority_over_meminfo(self):
        (self.cgroup_root / "memory.max").write_text(str(int(1.5 * GIB)), encoding="utf-8")
        self._write_meminfo(16 * 1024 * 1024)

        profile = resolve_runtime_profile(cgroup_root=self.cgroup_root, meminfo_path=self.meminfo_path, environ={})

        self.assertEqual("cgroup-v2", profile.memory_source)
        self.assertEqual(int(1.5 * GIB), profile.memory_bytes)
        self.assertEqual((2, 1, 32), (profile.slot_count, profile.dial_workers, profile.max_connections))

    def test_cgroup_v1_limit_is_supported(self):
        memory_dir = self.cgroup_root / "memory"
        memory_dir.mkdir()
        (memory_dir / "memory.limit_in_bytes").write_text(str(2 * GIB), encoding="utf-8")
        self._write_meminfo(16 * 1024 * 1024)

        profile = resolve_runtime_profile(cgroup_root=self.cgroup_root, meminfo_path=self.meminfo_path, environ={})

        self.assertEqual("cgroup-v1", profile.memory_source)
        self.assertEqual((4, 2, 64), (profile.slot_count, profile.dial_workers, profile.max_connections))

    def test_unlimited_cgroup_uses_meminfo(self):
        (self.cgroup_root / "memory.max").write_text("max", encoding="utf-8")
        self._write_meminfo(3 * 1024 * 1024)

        profile = resolve_runtime_profile(cgroup_root=self.cgroup_root, meminfo_path=self.meminfo_path, environ={})

        self.assertEqual("meminfo", profile.memory_source)
        self.assertEqual((8, 2, 128), (profile.slot_count, profile.dial_workers, profile.max_connections))

    def test_profile_boundaries(self):
        for memory_bytes, expected in (
            (int(1.5 * GIB), (2, 1, 32)),
            (int(1.5 * GIB) + 1, (4, 2, 64)),
            (int(2.5 * GIB), (4, 2, 64)),
            (int(2.5 * GIB) + 1, (8, 2, 128)),
            (4 * GIB, (8, 2, 128)),
            (4 * GIB + 1, (34, 4, 256)),
        ):
            with self.subTest(memory_bytes=memory_bytes):
                (self.cgroup_root / "memory.max").write_text(str(memory_bytes), encoding="utf-8")
                profile = resolve_runtime_profile(
                    cgroup_root=self.cgroup_root,
                    meminfo_path=self.meminfo_path,
                    environ={},
                )
                self.assertEqual(expected, (profile.slot_count, profile.dial_workers, profile.max_connections))

    def test_unknown_memory_uses_conservative_defaults(self):
        profile = resolve_runtime_profile(
            cgroup_root=self.cgroup_root,
            meminfo_path=self.meminfo_path,
            environ={},
        )

        self.assertEqual("unknown", profile.memory_source)
        self.assertEqual((4, 2, 64), (profile.slot_count, profile.dial_workers, profile.max_connections))

    def test_explicit_overrides_take_priority(self):
        (self.cgroup_root / "memory.max").write_text(str(GIB), encoding="utf-8")

        profile = resolve_runtime_profile(
            cgroup_root=self.cgroup_root,
            meminfo_path=self.meminfo_path,
            environ={
                "KUI_SLOT_COUNT": "8",
                "KUI_DIAL_WORKERS": "3",
                "PROXY_MAX_CONNECTIONS": "200",
            },
        )

        self.assertEqual((8, 3, 200), (profile.slot_count, profile.dial_workers, profile.max_connections))

    def test_auto_slot_override_uses_detected_profile(self):
        (self.cgroup_root / "memory.max").write_text(str(GIB), encoding="utf-8")

        profile = resolve_runtime_profile(
            cgroup_root=self.cgroup_root,
            meminfo_path=self.meminfo_path,
            environ={"KUI_SLOT_COUNT": "auto"},
        )

        self.assertEqual(2, profile.slot_count)

    def test_explicit_34_slot_override_is_supported(self):
        profile = resolve_runtime_profile(
            cgroup_root=self.cgroup_root,
            meminfo_path=self.meminfo_path,
            environ={"KUI_SLOT_COUNT": "34"},
        )

        self.assertEqual(34, profile.slot_count)

    def test_35_slot_override_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "KUI_SLOT_COUNT"):
            resolve_runtime_profile(
                cgroup_root=self.cgroup_root,
                meminfo_path=self.meminfo_path,
                environ={"KUI_SLOT_COUNT": "35"},
            )

    def test_invalid_overrides_are_rejected(self):
        cases = (
            ({"KUI_SLOT_COUNT": "0"}, "KUI_SLOT_COUNT"),
            ({"KUI_SLOT_COUNT": "twenty"}, "KUI_SLOT_COUNT"),
            ({"KUI_SLOT_COUNT": "2", "KUI_DIAL_WORKERS": "3"}, "KUI_DIAL_WORKERS"),
            ({"PROXY_MAX_CONNECTIONS": "0"}, "PROXY_MAX_CONNECTIONS"),
        )
        for environ, error in cases:
            with self.subTest(environ=environ):
                with self.assertRaisesRegex(ValueError, error):
                    resolve_runtime_profile(
                        cgroup_root=self.cgroup_root,
                        meminfo_path=self.meminfo_path,
                        environ=environ,
                    )


if __name__ == "__main__":
    unittest.main()
