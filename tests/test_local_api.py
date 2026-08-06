import base64
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from vps.local_api import LocalAPIServer
from vps.store import LocalStore


class FakeManager:
    def __init__(self, store):
        self.store = store
        self.actions = []

    def snapshot(self):
        return [slot.as_dict() for slot in self.store.list_slots()]

    def redial_slot(self, slot_id):
        self.actions.append(("redial", slot_id))
        return self.store.get_slot(slot_id)

    def connect_slot(self, slot_id, node_ip):
        self.actions.append(("connect", slot_id, node_ip))
        return self.store.get_slot(slot_id)

    def enable_slot(self, slot_id):
        self.actions.append(("enable", slot_id))
        return self.store.enable_slot(slot_id)

    def disable_slot(self, slot_id):
        self.actions.append(("disable", slot_id))
        return self.store.update_slot(slot_id, enabled=False)

    def start_slot(self, slot_id):
        self.actions.append(("start", slot_id))
        return self.store.get_slot(slot_id)

    def stop_slot(self, slot_id):
        self.actions.append(("stop", slot_id))

    def list_nodes(self, country="ANY"):
        return []


class LocalAPITest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = LocalStore(Path(self.tempdir.name) / "state.db")
        self.store.initialize()
        self.manager = FakeManager(self.store)
        self.server = LocalAPIServer(
            ("127.0.0.1", 0),
            store=self.store,
            manager=self.manager,
            web_root=Path(self.tempdir.name),
            username="admin",
            password="secret",
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        token = base64.b64encode(b"admin:secret").decode()
        self.auth = {"Authorization": f"Basic {token}"}

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.tempdir.cleanup()

    def request(self, path, *, method="GET", body=None, authenticated=True, expect_json=True):
        headers = {"Content-Type": "application/json"}
        if authenticated:
            headers.update(self.auth)
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                raw = response.read()
                return response.status, json.loads(raw) if expect_json else raw.decode()
        except urllib.error.HTTPError as error:
            try:
                raw = error.read()
                return error.code, json.loads(raw) if expect_json else raw.decode()
            finally:
                error.close()

    def test_login_returns_bearer_token_for_kui_frontend(self):
        status, body = self.request(
            "/api/login",
            method="POST",
            body={"username": "admin", "password": "secret"},
            authenticated=False,
        )

        self.assertEqual(200, status)
        self.assertEqual("admin", body["username"])
        self.assertEqual("admin", body["role"])
        self.assertTrue(body["token"])

    def test_bearer_token_authenticates_local_api(self):
        status, login = self.request(
            "/api/login",
            method="POST",
            body={"username": "admin", "password": "secret"},
            authenticated=False,
        )
        self.assertEqual(200, status)

        request = urllib.request.Request(
            self.base + "/api/local/exits",
            headers={"Authorization": f"Bearer {login['token']}"},
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            body = json.loads(response.read())

        self.assertEqual(12, len(body["exits"]))

    def test_management_api_accessible_without_login_in_local_mode(self):
        status, body = self.request("/api/local/exits", authenticated=False)

        self.assertEqual(200, status)

    def test_dashboard_asset_is_loadable_before_frontend_login(self):
        (Path(self.tempdir.name) / "index.html").write_text("<title>K-UI Local</title>", encoding="utf-8")
        request = urllib.request.Request(self.base + "/", method="GET")

        with urllib.request.urlopen(request, timeout=3) as response:
            body = response.read().decode("utf-8")

        self.assertEqual(200, response.status)
        self.assertIn("K-UI Local", body)

    def test_lists_all_exit_slots(self):
        status, body = self.request("/api/local/exits")

        self.assertEqual(200, status)
        self.assertEqual(12, len(body["exits"]))

    def test_kui_data_endpoint_returns_local_dashboard_shape(self):
        status, body = self.request("/api/data")

        self.assertEqual(200, status)
        self.assertEqual([], body["servers"])
        self.assertEqual("local", body["mode"])

    def test_kui_stats_endpoint_returns_empty_history_for_local_mode(self):
        status, body = self.request("/api/stats?ip=local")

        self.assertEqual(200, status)
        self.assertEqual([], body)

    def test_ui_ping_accepts_frontend_keepalive(self):
        status, body = self.request("/api/ui_ping", method="POST", body={})

        self.assertEqual(200, status)
        self.assertTrue(body["success"])

    def test_probe_public_endpoint_returns_local_dashboard_shape(self):
        status, body = self.request("/api/probe/public?ajax=1")

        self.assertEqual(200, status)
        self.assertEqual([], body["servers"])
        self.assertEqual("", body["realtime_url"])
        self.assertEqual("false", body["settings"]["is_public"])
        self.assertIn("cached_nodes_data", body["settings"])

    def test_probe_admin_data_endpoint_returns_local_settings_shape(self):
        status, body = self.request("/api/probe/admin/data")

        self.assertEqual(200, status)
        self.assertEqual([], body["servers"])
        self.assertEqual("false", body["settings"]["is_public"])
        self.assertIn("cached_nodes_data", body["settings"])

    @patch("vps.local_api.fetch_countries", return_value=["CA", "JP", "US"])
    def test_proxy_status_endpoints_reflect_local_exit_slots(self, _mock_fetch_countries):
        countries_status, countries = self.request("/api/proxy/countries")
        config_status, config = self.request("/api/proxy/config")
        pool_status, pool = self.request("/api/proxy/pool")
        nodes_status, nodes = self.request("/api/proxy/nodes")

        self.assertEqual(200, countries_status)
        self.assertIn("JP", countries)
        self.assertIn("US", countries)
        self.assertEqual(sorted(countries), countries)
        self.assertEqual(200, config_status)
        self.assertEqual("JP", config["0"])
        self.assertEqual(7920, config["port"])
        self.assertEqual("JP", config["proxy"]["country"])
        self.assertEqual(7920, config["proxy"]["port"])
        self.assertEqual(200, pool_status)
        self.assertEqual(200, nodes_status)
        self.assertEqual(1, len(pool))
        self.assertEqual(1, len(nodes))
        self.assertEqual("local", pool[0]["ip"])
        self.assertEqual("local", nodes[0]["ip"])
        details = json.loads(nodes[0]["details"])
        self.assertEqual(12, len(details))
        self.assertEqual("exit-01", details[0]["tunnel"])
        self.assertEqual("JP", details[0]["country"])
        self.assertEqual(7920, details[0]["port"])

    def test_proxy_extraction_returns_usable_local_socks5_lines(self):
        request = urllib.request.Request(self.base + "/api/proxy/proxies", headers=self.auth)
        with urllib.request.urlopen(request, timeout=3) as response:
            body = response.read().decode("utf-8")

        lines = body.strip().splitlines()
        self.assertEqual(12, len(lines))
        self.assertTrue(lines[0].startswith("socks5://admin:secret@127.0.0.1:7920#"))
        self.assertIn("exit-01", lines[0])
        self.assertIn("JP", lines[0])

    def test_updates_country_and_port_then_restarts_only_slot(self):
        status, body = self.request(
            "/api/local/exits/exit-01",
            method="PUT",
            body={"country": "CA", "proxy_port": 9001},
        )

        self.assertEqual(200, status)
        self.assertEqual("CA", body["exit"]["country"])
        self.assertEqual(9001, body["exit"]["proxy_port"])
        self.assertIn(("stop", "exit-01"), self.manager.actions)
        self.assertIn(("start", "exit-01"), self.manager.actions)

    def test_rejects_invalid_country_with_stable_error(self):
        status, body = self.request(
            "/api/local/exits/exit-01",
            method="PUT",
            body={"country": "JAPAN"},
        )

        self.assertEqual(400, status)
        self.assertEqual("invalid_request", body["code"])

    def test_redial_and_enable_actions(self):
        redial_status, _ = self.request("/api/local/exits/exit-02/redial", method="POST", body={})
        enable_status, _ = self.request("/api/local/exits/exit-02/enable", method="POST", body={})

        self.assertEqual(202, redial_status)
        self.assertEqual(202, enable_status)
        self.assertIn(("redial", "exit-02"), self.manager.actions)
        self.assertIn(("enable", "exit-02"), self.manager.actions)

    def test_connect_action_dials_selected_candidate_node(self):
        status, body = self.request(
            "/api/local/exits/exit-02/connect",
            method="POST",
            body={"node_ip": "198.51.100.8"},
        )

        self.assertEqual(202, status)
        self.assertTrue(body["accepted"])
        self.assertIn(("connect", "exit-02", "198.51.100.8"), self.manager.actions)

    def test_connect_action_rejects_missing_candidate_ip(self):
        status, body = self.request(
            "/api/local/exits/exit-02/connect",
            method="POST",
            body={},
        )

        self.assertEqual(400, status)
        self.assertEqual("invalid_request", body["code"])

    def test_healthz_does_not_require_authentication(self):
        status, body = self.request("/healthz", authenticated=False)

        self.assertEqual(200, status)
        self.assertTrue(body["ok"])

    def test_vps_crud_lifecycle(self):
        status, created = self.request("/api/vps", method="POST", body={"ip": "10.0.0.1", "name": "test-vps"})
        self.assertEqual(200, status)
        self.assertEqual("10.0.0.1", created["ip"])

        status, listed = self.request("/api/vps")
        self.assertEqual(200, status)
        self.assertTrue(any(v["ip"] == "10.0.0.1" for v in listed))

        status, updated = self.request("/api/vps", method="PUT", body={"ip": "10.0.0.1", "name": "renamed"})
        self.assertEqual(200, status)
        self.assertEqual("renamed", updated["name"])

        status, _ = self.request("/api/vps?ip=10.0.0.1", method="DELETE")
        self.assertEqual(200, status)

        status, listed = self.request("/api/vps")
        self.assertEqual(200, status)
        self.assertFalse(any(v["ip"] == "10.0.0.1" for v in listed))

    def test_node_crud_lifecycle(self):
        status, created = self.request("/api/nodes", method="POST", body={"ip": "10.0.0.2", "name": "node1", "protocol": "socks5"})
        self.assertEqual(200, status)
        self.assertEqual("10.0.0.2", created["ip"])

        status, listed = self.request("/api/nodes")
        self.assertEqual(200, status)
        self.assertTrue(any(n["ip"] == "10.0.0.2" for n in listed))

        status, updated = self.request("/api/nodes", method="PUT", body={"id": created["id"], "enable": False})
        self.assertEqual(200, status)
        self.assertEqual(0, updated["enable"])

        status, _ = self.request(f"/api/nodes?id={created['id']}", method="DELETE")
        self.assertEqual(200, status)

    def test_user_crud_lifecycle(self):
        status, created = self.request("/api/users", method="POST", body={"username": "user1", "password": "password123", "traffic_limit": 1073741824})
        self.assertEqual(200, status)
        self.assertEqual("user1", created["username"])
        self.assertEqual("", created["password"])

        status, listed = self.request("/api/users")
        self.assertEqual(200, status)
        self.assertTrue(any(u["username"] == "user1" for u in listed))

        status, updated = self.request("/api/users", method="PUT", body={"username": "user1", "enable": False})
        self.assertEqual(200, status)
        self.assertEqual(0, updated["enable"])

        status, _ = self.request("/api/users?username=user1", method="DELETE")
        self.assertEqual(200, status)

    def test_settings_persist_and_return(self):
        status, _ = self.request("/api/settings", method="POST", body={"site_title": "My Panel"})
        self.assertEqual(200, status)

        status, data = self.request("/api/data")
        self.assertEqual(200, status)

        status, probe = self.request("/api/probe/admin/data")
        self.assertEqual(200, status)

    def test_thirdparty_crud_lifecycle(self):
        content = "vless://11111111-1111-1111-1111-111111111111@vpn.example.com:443#Tokyo"
        with patch("vps.local_api.fetch_subscription_text", return_value=content):
            status, created = self.request(
                "/api/thirdparty",
                method="POST",
                body={"name": "sub1", "url": "https://subscription.example.com/profile"},
            )
        self.assertEqual(200, status)

        status, listed = self.request("/api/thirdparty")
        self.assertEqual(200, status)
        subscription = next(t for t in listed if t["name"] == "sub1")

        status, updated = self.request("/api/thirdparty", method="PUT", body={"id": subscription["id"], "enable": False})
        self.assertEqual(200, status)
        self.assertEqual(0, updated["is_enable"])

        status, _ = self.request(f"/api/thirdparty?id={subscription['id']}", method="DELETE")
        self.assertEqual(200, status)

    def test_thirdparty_import_parses_and_persists_nodes(self):
        content = (
            "vless://11111111-1111-1111-1111-111111111111@vpn.example.com:443"
            "?encryption=none&security=reality&sni=www.example.com&pbk=public-key&sid=abcd"
            "&flow=xtls-rprx-vision&type=tcp#Tokyo"
        )
        with patch("vps.local_api.fetch_subscription_text", create=True, return_value=content):
            status, created = self.request(
                "/api/thirdparty",
                method="POST",
                body={"name": "sub1", "url": "https://subscription.example.com/profile"},
            )

        self.assertEqual(200, status)
        self.assertEqual(1, created["parsedCount"])
        status, listed = self.request("/api/thirdparty")
        self.assertEqual(200, status)
        self.assertEqual(1, listed[0]["node_count"])
        self.assertEqual(1, listed[0]["is_enable"])
        self.assertGreater(listed[0]["added_at"], 0)

    def test_subscription_endpoint_merges_enabled_thirdparty_nodes(self):
        content = "vless://11111111-1111-1111-1111-111111111111@vpn.example.com:443#Tokyo"
        with patch("vps.local_api.fetch_subscription_text", return_value=content):
            status, created = self.request(
                "/api/thirdparty",
                method="POST",
                body={"name": "sub1", "url": "https://subscription.example.com/profile"},
            )
        self.assertEqual(200, status)

        status, data = self.request("/api/data")
        self.assertEqual(200, status)
        token = data["mySubToken"]
        status, encoded = self.request(f"/api/sub?user=admin&token={token}", expect_json=False)
        self.assertEqual(200, status)
        links = base64.b64decode(encoded).decode()
        self.assertIn("vless://11111111-1111-1111-1111-111111111111@vpn.example.com:443", links)

        status, listed = self.request("/api/thirdparty")
        self.assertEqual(200, status)
        status, _ = self.request(
            "/api/thirdparty",
            method="PUT",
            body={"id": listed[0]["id"], "enable": False},
        )
        self.assertEqual(200, status)
        status, encoded = self.request(f"/api/sub?user=admin&token={token}", expect_json=False)
        self.assertEqual(200, status)
        links = base64.b64decode(encoded).decode()
        self.assertNotIn("vpn.example.com", links)

    def test_subscription_endpoint_includes_enabled_local_exit_socks5_nodes(self):
        status, data = self.request("/api/data")
        self.assertEqual(200, status)
        token = data["mySubToken"]

        status, encoded = self.request(f"/api/sub?user=admin&token={token}", expect_json=False)

        self.assertEqual(200, status)
        links = base64.b64decode(encoded).decode().splitlines()
        self.assertEqual(12, len(links))
        self.assertTrue(links[0].startswith("socks5://admin:secret@127.0.0.1:7920#JP_exit-01_"))

    def test_subscription_clash_format_includes_enabled_local_exit_socks5_nodes(self):
        status, data = self.request("/api/data")
        self.assertEqual(200, status)
        token = data["mySubToken"]

        status, body = self.request(f"/api/sub?user=admin&token={token}&format=clash", expect_json=False)

        self.assertEqual(200, status)
        self.assertIn("type: socks5", body)
        self.assertIn("server: 127.0.0.1", body)
        self.assertIn("port: 7920", body)
        self.assertIn("exit-01", body)

    def test_subscription_excludes_disabled_local_exit_socks5_nodes(self):
        self.request("/api/local/exits/exit-01/disable", method="POST", body={})
        status, data = self.request("/api/data")
        self.assertEqual(200, status)
        token = data["mySubToken"]

        status, encoded = self.request(f"/api/sub?user=admin&token={token}", expect_json=False)

        self.assertEqual(200, status)
        links = base64.b64decode(encoded).decode()
        self.assertNotIn(":7920#JP_exit-01_", links)

    def test_proxy_switch_delegates_to_slot_redial(self):
        status, result = self.request("/api/proxy/switch", method="POST", body={"country": "JP", "port": 7920})
        self.assertEqual(202, status)
        self.assertTrue(result["accepted"])
        self.assertIn(("redial", "exit-01"), self.manager.actions)

    def test_local_nodes_endpoint_returns_candidate_list(self):
        status, nodes = self.request("/api/local/nodes?country=JP")
        self.assertEqual(200, status)
        self.assertIsInstance(nodes, list)

    def test_user_password_change_requires_minimum_length(self):
        status, body = self.request("/api/user/password", method="PUT", body={"password": "short"})
        self.assertEqual(400, status)
        self.assertEqual("invalid_request", body["code"])

    def test_testisp_lookup_returns_upstream_report(self):
        report = {
            "geo": {"country": "Japan", "country_code": "JP", "is_native": True},
            "isp": {"flag": "isp", "type": "broadband", "org": "Example ISP"},
        }
        with patch("vps.local_api.fetch_testisp_report", create=True, return_value=report) as fetch_report:
            status, body = self.request("/api/proxy/testisp-lookup/203.0.113.9")

        self.assertEqual(200, status)
        self.assertEqual(report, body)
        fetch_report.assert_called_once_with("203.0.113.9")

    def test_probe_detail_returns_not_found_for_unknown_local_probe(self):
        status, body = self.request("/api/probe/detail?id=missing")

        self.assertEqual(404, status)
        self.assertEqual("not_found", body["code"])

    @patch("vps.local_api.fetch_github_probe_data", create=True, return_value={"themes": [{"id": "theme2"}], "ct": ["1.1.1.1"]})
    def test_probe_admin_pull_github_persists_downloaded_data(self, fetch_nodes):
        status, body = self.request("/api/probe/admin/pull_github", method="POST", body={})

        self.assertEqual(200, status)
        self.assertTrue(body["success"])
        fetch_nodes.assert_called_once_with()
        status, probe = self.request("/api/probe/admin/data")
        self.assertEqual(200, status)
        self.assertEqual(
            {"themes": [{"id": "theme2"}], "ct": ["1.1.1.1"]},
            json.loads(probe["settings"]["cached_nodes_data"]),
        )

    def test_probe_settings_save_and_reflect(self):
        status, body = self.request(
            "/api/probe/admin/settings",
            method="POST",
            body={"settings": {"is_public": "true", "site_title": "Probe Title"}},
        )
        self.assertEqual(200, status)
        self.assertTrue(body["success"])

        status, probe = self.request("/api/probe/admin/data")
        self.assertEqual(200, status)
        self.assertEqual("true", probe["settings"]["is_public"])
        self.assertEqual("Probe Title", probe["settings"]["site_title"])

    @patch("vps.local_api.set_credentials")
    def test_user_password_change_succeeds_and_updates_login(self, set_credentials):
        status, body = self.request("/api/user/password", method="PUT", body={"password": "newpass123"})
        self.assertEqual(200, status)
        self.assertTrue(body["success"])
        set_credentials.assert_called_once_with("admin", "newpass123")

        login_status, login_body = self.request(
            "/api/login",
            method="POST",
            body={"username": "admin", "password": "newpass123"},
            authenticated=False,
        )
        self.assertEqual(200, login_status)
        self.assertTrue(login_body["token"])

    def test_sub_token_reset_returns_new_token(self):
        status, body = self.request("/api/user/sub_token", method="PUT", body={})
        self.assertEqual(200, status)
        self.assertTrue(body["sub_token"])

    def test_proxy_config_post_updates_slot_country(self):
        status, body = self.request(
            "/api/proxy/config",
            method="POST",
            body={"ip": "local", "0": "US", "country": "US", "port": 7920},
        )
        self.assertEqual(200, status)
        self.assertEqual("US", body["country"])
        self.assertEqual("US", body["0"])
        self.assertEqual(7920, body["port"])

    def test_proxy_config_post_with_switch_trigger_redials(self):
        self.manager.actions.clear()
        status, body = self.request(
            "/api/proxy/config",
            method="POST",
            body={"ip": "local", "0": "JP", "country": "JP", "port": 7920, "switch_trigger": 12345},
        )
        self.assertEqual(200, status)
        self.assertEqual(12345, body["switch_trigger"])
        self.assertIn(("redial", "exit-01"), self.manager.actions)

    def test_data_endpoint_returns_stored_vps_and_users(self):
        self.request("/api/vps", method="POST", body={"ip": "10.0.0.5", "name": "srv5"})
        self.request("/api/users", method="POST", body={"username": "alice", "password": "password123"})

        status, data = self.request("/api/data")
        self.assertEqual(200, status)
        self.assertTrue(any(s["ip"] == "10.0.0.5" for s in data["servers"]))
        self.assertTrue(any(u["username"] == "alice" for u in data["users"]))
        self.assertEqual("", data["users"][0]["password"])

    def test_probe_public_reflects_saved_settings(self):
        self.request("/api/probe/admin/settings", method="POST", body={"settings": {"site_title": "Public Title"}})

        status, body = self.request("/api/probe/public?ajax=1")
        self.assertEqual(200, status)
        self.assertEqual("Public Title", body["settings"]["site_title"])

    def test_delete_vps_also_removes_associated_nodes(self):
        self.request("/api/vps", method="POST", body={"ip": "10.0.0.9", "name": "srv9"})
        self.request("/api/nodes", method="POST", body={"ip": "10.0.0.9", "name": "node9", "protocol": "XTLS-Reality"})

        status, nodes = self.request("/api/nodes")
        self.assertTrue(any(n["ip"] == "10.0.0.9" for n in nodes))

        self.request("/api/vps?ip=10.0.0.9", method="DELETE")

        status, nodes = self.request("/api/nodes")
        self.assertFalse(any(n["ip"] == "10.0.0.9" for n in nodes))


if __name__ == "__main__":
    unittest.main()
