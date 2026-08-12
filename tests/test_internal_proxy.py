import json
import tempfile
import unittest
from pathlib import Path

from vps.internal_proxy import (
    load_internal_proxy_credentials,
    load_or_create_internal_proxy_credentials,
)


class InternalProxyCredentialsTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.tempdir.name)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_generated_credentials_are_stable_and_owner_only(self):
        first = load_or_create_internal_proxy_credentials(self.workspace, environ={})
        credentials_file = self.workspace / "internal_proxy.json"
        second = load_or_create_internal_proxy_credentials(self.workspace, environ={})

        self.assertEqual(first, second)
        self.assertEqual("kui-gateway", first[0])
        self.assertGreater(len(first[1]), 20)
        self.assertEqual("0o600", oct(credentials_file.stat().st_mode & 0o777))
        stored = json.loads(credentials_file.read_text(encoding="utf-8"))
        self.assertEqual(first[1], stored["password"])

    def test_gateway_reader_reuses_persisted_credentials_without_creating_them(self):
        created = load_or_create_internal_proxy_credentials(self.workspace, environ={})

        loaded = load_internal_proxy_credentials(self.workspace, environ={})

        self.assertEqual(created, loaded)
        with self.assertRaisesRegex(RuntimeError, "unavailable"):
            load_internal_proxy_credentials(Path(self.tempdir.name) / "missing", environ={})

    def test_explicit_credentials_do_not_write_runtime_file(self):
        credentials = load_or_create_internal_proxy_credentials(
            self.workspace,
            environ={
                "KUI_INTERNAL_PROXY_USER": "gateway",
                "KUI_INTERNAL_PROXY_PASSWORD": "stable-password",
            },
        )

        self.assertEqual(("gateway", "stable-password"), credentials)
        self.assertFalse((self.workspace / "internal_proxy.json").exists())

    def test_partial_explicit_credentials_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "set together"):
            load_or_create_internal_proxy_credentials(
                self.workspace,
                environ={"KUI_INTERNAL_PROXY_USER": "gateway"},
            )


if __name__ == "__main__":
    unittest.main()
