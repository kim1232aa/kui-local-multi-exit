import base64
import json
import os
import re
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from vps.local_api import LocalAPIHandler, LocalAPIServer
from vps.realm_manager import RealmManager
from vps.store import LocalStore


class FakeManager:
    def __init__(self, store):
        self.store = store
        self.actions = []
        self.listener_states = {}

    def snapshot(self):
        return [slot.as_dict() for slot in self.store.list_slots()]

    def listener_ready(self, slot_id):
        return self.listener_states.get(
            slot_id,
            self.store.get_slot(slot_id).state == "ready",
        )

    def set_slot_ready(self, slot_id, *, listener_ready=True):
        self.store.set_runtime(
            slot_id,
            state="ready",
            entry_ip="198.51.100.1",
            egress_ip="203.0.113.1",
        )
        self.listener_states[slot_id] = listener_ready

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

    def is_managed_slot(self, slot_id):
        return any(slot.id == slot_id for slot in self.store.list_slots())

    def list_nodes(self, country="ANY"):
        return []


class LocalAPITest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = LocalStore(Path(self.tempdir.name) / "state.db")
        self.store.initialize()
        self.manager = FakeManager(self.store)
        self.realm_processes = []

        class RealmProcess:
            def __init__(process_self):
                process_self.returncode = None

            def poll(process_self):
                return process_self.returncode

            def terminate(process_self):
                process_self.returncode = 0

            def wait(process_self, timeout=None):
                return process_self.returncode

            def kill(process_self):
                process_self.returncode = -9

        def start_realm(command, **kwargs):
            process = RealmProcess()
            self.realm_processes.append((command, process))
            return process

        self.realm_manager = RealmManager(
            self.store,
            binary="/usr/local/bin/realm",
            popen=start_realm,
        )
        self.server = LocalAPIServer(
            ("127.0.0.1", 0),
            store=self.store,
            manager=self.manager,
            realm_manager=self.realm_manager,
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

    def request_text_with_content_type(self, path, *, authenticated=True):
        headers = dict(self.auth) if authenticated else {}
        request = urllib.request.Request(self.base + path, headers=headers)
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, response.headers.get_content_type(), response.read().decode("utf-8")

    def test_management_api_accessible_without_login_in_local_mode(self):
        status, body = self.request("/api/local/exits", authenticated=False)

        self.assertEqual(200, status)

    def test_management_login_endpoint_is_removed(self):
        status, body = self.request(
            "/api/login",
            method="POST",
            body={"username": "admin", "password": "secret"},
            authenticated=False,
        )

        self.assertEqual(404, status)
        self.assertEqual("not_found", body["code"])

    def test_idle_slots_are_not_published(self):
        status, body = self.request("/api/proxy/proxies", authenticated=False, expect_json=False)

        self.assertEqual(200, status)
        self.assertEqual("", body.strip())

    def test_only_ready_listener_slots_are_published(self):
        self.store.set_runtime(
            "exit-01",
            state="ready",
            entry_ip="198.51.100.1",
            egress_ip="203.0.113.1",
        )
        status, body = self.request("/api/proxy/proxies", authenticated=False, expect_json=False)

        self.assertEqual(200, status)
        self.assertIn(":7920#", body)
        self.assertNotIn(":7921#", body)

    def test_invalid_update_does_not_stop_ready_slot(self):
        self.store.set_runtime("exit-01", state="ready")

        status, body = self.request(
            "/api/local/exits/exit-01",
            method="PUT",
            body={"proxy_port": 9001},
        )

        self.assertEqual(400, status)
        self.assertNotIn(("stop", "exit-01"), self.manager.actions)

    def test_proxy_switch_requires_explicit_slot(self):
        status, body = self.request(
            "/api/proxy/switch",
            method="POST",
            body={"ip": "10.0.0.8"},
        )

        self.assertEqual(400, status)
        self.assertEqual("slot_id is required", body["error"])

    def test_dashboard_asset_is_loadable_before_frontend_login(self):
        (Path(self.tempdir.name) / "index.html").write_text("<title>K-UI Local</title>", encoding="utf-8")
        request = urllib.request.Request(self.base + "/", method="GET")

        with urllib.request.urlopen(request, timeout=3) as response:
            body = response.read().decode("utf-8")

        self.assertEqual(200, response.status)
        self.assertIn("K-UI Local", body)

    def test_lists_all_exit_slots(self):
        self.store.set_runtime(
            "exit-01",
            state="ready",
            egress_ip="203.0.113.1",
            check_result={
                "residential": {
                    "status": "checked",
                    "egress_type": "datacenter",
                    "egress_type_label": "机房IP",
                    "is_residential": False,
                }
            },
        )
        status, body = self.request("/api/local/exits")

        self.assertEqual(200, status)
        self.assertEqual(24, len(body["exits"]))
        slot = next(item for item in body["exits"] if item["id"] == "exit-01")
        self.assertEqual("datacenter", slot["egress_type"])
        self.assertEqual("机房IP", slot["egress_type_label"])

        status, status_body = self.request("/api/local/status")
        self.assertEqual(200, status)
        status_slot = next(item for item in status_body["exits"] if item["id"] == "exit-01")
        self.assertEqual("机房IP", status_slot["egress_type_label"])

    def test_kui_data_endpoint_returns_local_dashboard_shape(self):
        status, body = self.request("/api/data")

        self.assertEqual(200, status)
        self.assertEqual([], body["servers"])
        self.assertEqual("local", body["mode"])

    def test_kui_stats_endpoint_reflects_persisted_events_and_checks(self):
        self.store.record_event("exit-01", "connected", "tunnel ready")
        generation = self.store.get_slot("exit-01").generation
        self.store.append_check_result(
            "exit-01",
            generation,
            {"accepted": True, "egress_ip": "203.0.113.1"},
        )

        status, body = self.request("/api/stats?ip=local")

        self.assertEqual(200, status)
        self.assertEqual(1, len(body))
        self.assertEqual(1, body[0]["event_count"])
        self.assertEqual(1, body[0]["check_count"])
        self.assertEqual(1, body[0]["accepted_checks"])
        self.assertEqual(0, body[0]["total_bytes"])
        self.assertRegex(body[0]["day"], r"^\d{4}-\d{2}-\d{2}$")

    def test_ui_ping_accepts_frontend_keepalive(self):
        status, body = self.request("/api/ui_ping", method="POST", body={})

        self.assertEqual(200, status)
        self.assertTrue(body["success"])

    def test_probe_public_endpoint_projects_all_local_slots(self):
        self.store.set_runtime(
            "exit-01",
            state="ready",
            egress_ip="203.0.113.1",
            check_result={"targets": {"accepted": True}},
        )
        self.manager.listener_states["exit-01"] = True

        status, body = self.request("/api/probe/public?ajax=1")

        self.assertEqual(200, status)
        self.assertEqual(24, len(body["servers"]))
        first = body["servers"][0]
        self.assertEqual("exit-01", first["id"])
        self.assertEqual("ready", first["state"])
        self.assertEqual("203.0.113.1", first["egress_ip"])
        self.assertEqual({"targets": {"accepted": True}}, first["check_result"])
        self.assertTrue(first["listener_ready"])
        self.assertGreater(first["updated_at"], 0)
        self.assertEqual(first["updated_at"] * 1000, first["last_updated"])
        self.assertEqual("0", first["ping_ct"])
        self.assertEqual("0", first["ping_cu"])
        self.assertEqual("0", first["ping_cm"])
        self.assertEqual("0", first["ping_bd"])
        self.assertEqual("0", first["cpu"])
        self.assertEqual("0", first["memory"])
        self.assertEqual("0", first["net_in_speed"])
        self.assertEqual("0", first["net_out_speed"])
        self.assertEqual("", body["realtime_url"])
        self.assertEqual("false", body["settings"]["is_public"])
        self.assertIn("cached_nodes_data", body["settings"])

    def test_probe_admin_data_projects_all_local_slots(self):
        status, body = self.request("/api/probe/admin/data")

        self.assertEqual(200, status)
        self.assertEqual(24, len(body["servers"]))
        self.assertEqual("exit-01", body["servers"][0]["id"])
        self.assertIn("listener_ready", body["servers"][0])
        self.assertEqual("false", body["settings"]["is_public"])
        self.assertIn("cached_nodes_data", body["settings"])

    def test_realm_api_configures_starts_restarts_and_stops_real_manager(self):
        initial_status, initial = self.request("/api/realm")
        configure_status, configured = self.request(
            "/api/realm",
            method="PUT",
            body={"listen": "0.0.0.0:5000", "remote": "1.1.1.1:443", "use_udp": True},
        )
        start_status, started = self.request(
            "/api/realm",
            method="POST",
            body={"action": "start"},
        )
        restart_status, restarted = self.request(
            "/api/realm",
            method="POST",
            body={"action": "restart"},
        )
        stop_status, stopped = self.request(
            "/api/realm",
            method="POST",
            body={"action": "stop"},
        )

        self.assertEqual(200, initial_status)
        self.assertTrue(initial["available"])
        self.assertFalse(initial["running"])
        self.assertEqual(200, configure_status)
        self.assertEqual("0.0.0.0:5000", configured["listen"])
        self.assertEqual("1.1.1.1:443", configured["remote"])
        self.assertTrue(configured["use_udp"])
        self.assertEqual(200, start_status)
        self.assertTrue(started["running"])
        self.assertEqual(
            ["/usr/local/bin/realm", "-u", "-l", "0.0.0.0:5000", "-r", "1.1.1.1:443"],
            self.realm_processes[0][0],
        )
        self.assertEqual(200, restart_status)
        self.assertTrue(restarted["running"])
        self.assertEqual(2, len(self.realm_processes))
        self.assertEqual(200, stop_status)
        self.assertFalse(stopped["running"])

    def test_local_deploy_command_contains_only_local_compose_workflow(self):
        status, body = self.request("/api/local/deploy-command")

        self.assertEqual(200, status)
        self.assertEqual("https://github.com/kim1232aa/kui-local-multi-exit.git", body["repository_url"])
        self.assertEqual("docker compose up -d --build", body["compose_command"])
        self.assertIn("KUI_MANAGEMENT_PASSWORD", body["environment"])
        serialized = json.dumps(body)
        self.assertNotIn("agent_token", serialized)
        self.assertNotIn("agent_update", serialized)
        self.assertNotIn("apk ", serialized)

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
        self.assertEqual(24, len(details))
        self.assertEqual("exit-01", details[0]["tunnel"])
        self.assertEqual("JP", details[0]["country"])
        self.assertEqual(7920, details[0]["port"])

    def test_proxy_extraction_returns_usable_local_socks5_lines(self):
        self.manager.set_slot_ready("exit-01")
        request = urllib.request.Request(self.base + "/api/proxy/proxies", headers=self.auth)
        with urllib.request.urlopen(request, timeout=3) as response:
            body = response.read().decode("utf-8")

        lines = body.strip().splitlines()
        self.assertEqual(1, len(lines))
        self.assertTrue(lines[0].startswith("socks5://admin:secret@127.0.0.1:7920#"))
        self.assertIn("exit-01", lines[0])
        self.assertIn("JP", lines[0])

    def test_updates_country_then_restarts_only_slot(self):
        status, body = self.request(
            "/api/local/exits/exit-01",
            method="PUT",
            body={"country": "CA"},
        )

        self.assertEqual(200, status)
        self.assertEqual("CA", body["exit"]["country"])
        self.assertEqual(7920, body["exit"]["proxy_port"])
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

    def test_inactive_runtime_slot_returns_not_found(self):
        self.manager.is_managed_slot = lambda slot_id: slot_id in {"exit-01", "exit-02"}

        status, body = self.request("/api/local/exits/exit-03/redial", method="POST", body={})

        self.assertEqual(404, status)
        self.assertEqual("not_found", body["code"])
        self.assertEqual([], self.manager.actions)

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

    def test_vps_crud_preserves_complete_management_contract(self):
        created_payload = {
            "ip": "10.0.0.11",
            "name": "edge-jp",
            "os": "ubuntu",
            "egress_mode": "socks5",
            "proxy_mode": "include",
            "proxy_categories": "video,ai",
            "egress_revision": 7,
            "egress_status": "pending",
            "egress_applied_mode": "direct",
            "egress_applied_revision": 6,
            "egress_error": "waiting for apply",
            "egress_ip": "203.0.113.11",
            "socks5_addr": "proxy.example.com",
            "socks5_port": 1080,
            "socks5_user": "proxy-user",
            "socks5_pass": "proxy-pass",
        }

        status, created = self.request("/api/vps", method="POST", body=created_payload)
        self.assertEqual(200, status)
        for key, value in created_payload.items():
            self.assertEqual(value, created[key], key)

        status, listed = self.request("/api/vps")
        self.assertEqual(200, status)
        stored = next(vps for vps in listed if vps["ip"] == created_payload["ip"])
        for key, value in created_payload.items():
            self.assertEqual(value, stored[key], key)

        updated_payload = {
            **created_payload,
            "name": "edge-jp-updated",
            "proxy_mode": "exclude",
            "proxy_categories": "social",
            "egress_revision": 8,
            "egress_status": "applied",
            "egress_applied_mode": "socks5",
            "egress_applied_revision": 8,
            "egress_error": "",
            "egress_ip": "203.0.113.12",
        }
        status, updated = self.request("/api/vps", method="PUT", body=updated_payload)
        self.assertEqual(200, status)
        for key, value in updated_payload.items():
            self.assertEqual(value, updated[key], key)

        status, listed = self.request("/api/vps")
        stored = next(vps for vps in listed if vps["ip"] == created_payload["ip"])
        for key, value in updated_payload.items():
            self.assertEqual(value, stored[key], key)

    def test_node_crud_preserves_complete_management_contract(self):
        created_payload = {
            "id": 77,
            "vps_ip": "10.0.0.12",
            "name": "reality-jp",
            "protocol": "Reality",
            "address": "vpn.example.com",
            "port": 443,
            "username": "node-user",
            "uuid": "11111111-1111-1111-1111-111111111111",
            "password": "node-pass",
            "sni": "www.example.com",
            "private_key": "private-key",
            "public_key": "public-key",
            "short_id": "abcd",
            "flow": "xtls-rprx-vision",
            "network": "tcp",
            "host": "cdn.example.com",
            "path": "/reality",
            "extra": "{\"fingerprint\":\"chrome\"}",
            "relay_type": "node",
            "target_ip": "198.51.100.12",
            "target_port": 8443,
            "target_id": 9,
            "traffic_limit": 1073741824,
            "expire_time": 2000000000,
        }

        status, created = self.request("/api/nodes", method="POST", body=created_payload)
        self.assertEqual(200, status)
        self.assertEqual(77, created["id"])
        self.assertEqual(created_payload["vps_ip"], created["ip"])
        for key, value in created_payload.items():
            self.assertEqual(value, created[key], key)

        status, listed = self.request("/api/nodes")
        self.assertEqual(200, status)
        stored = next(node for node in listed if node["id"] == 77)
        for key, value in created_payload.items():
            self.assertEqual(value, stored[key], key)

        updated_payload = {
            **created_payload,
            "name": "reality-jp-updated",
            "address": "vpn2.example.com",
            "port": 8443,
            "network": "ws",
            "host": "edge.example.com",
            "path": "/ws",
            "target_port": 9443,
        }
        status, updated = self.request("/api/nodes", method="PUT", body=updated_payload)
        self.assertEqual(200, status)
        for key, value in updated_payload.items():
            self.assertEqual(value, updated[key], key)

        status, listed = self.request("/api/nodes")
        stored = next(node for node in listed if node["id"] == 77)
        for key, value in updated_payload.items():
            self.assertEqual(value, stored[key], key)

    def test_vps_and_node_crud_reject_unknown_fields(self):
        requests = (
            ("/api/vps", "POST", {"ip": "10.0.0.21", "unknown": True}),
            ("/api/vps", "PUT", {"ip": "10.0.0.1", "unknown": True}),
            ("/api/nodes", "POST", {"vps_ip": "10.0.0.22", "unknown": True}),
            ("/api/nodes", "PUT", {"id": 1, "unknown": True}),
        )

        for path, method, payload in requests:
            with self.subTest(path=path, method=method):
                status, body = self.request(path, method=method, body=payload)
                self.assertEqual(400, status)
                self.assertEqual("unsupported_field", body["code"])

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
        status, encoded = self.request(f"/api/sub?user={data['mySubUser']}&token={token}", expect_json=False)
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
        status, encoded = self.request(f"/api/sub?user={data['mySubUser']}&token={token}", expect_json=False)
        self.assertEqual(200, status)
        links = base64.b64decode(encoded).decode()
        self.assertNotIn("vpn.example.com", links)

    def test_subscription_endpoint_includes_only_ready_listener_local_exits(self):
        self.manager.set_slot_ready("exit-01")
        status, data = self.request("/api/data")
        self.assertEqual(200, status)
        token = data["mySubToken"]

        status, encoded = self.request(f"/api/sub?user={data['mySubUser']}&token={token}", expect_json=False)

        self.assertEqual(200, status)
        links = base64.b64decode(encoded).decode().splitlines()
        self.assertEqual(1, len(links))
        self.assertTrue(links[0].startswith("socks5://admin:secret@127.0.0.1:7920#JP_exit-01_"))

    def test_configured_missing_reality_manifest_does_not_publish_loopback_socks(self):
        self.manager.set_slot_ready("exit-01")
        self.server.reality_nodes_file = Path(self.tempdir.name) / "missing-public-nodes.json"
        status, data = self.request("/api/data")
        token = data["mySubToken"]

        status, encoded = self.request(
            f"/api/sub?user={data['mySubUser']}&token={token}",
            expect_json=False,
        )

        self.assertEqual(200, status)
        self.assertEqual("", base64.b64decode(encoded).decode())

    def test_subscription_socks5_format_ignores_reality_manifest(self):
        self.manager.set_slot_ready("exit-01")
        self.server.reality_nodes_file = Path(self.tempdir.name) / "missing-public-nodes.json"
        status, data = self.request("/api/data")
        token = data["mySubToken"]

        status, encoded = self.request(
            f"/api/sub?user={data['mySubUser']}&token={token}&format=socks5",
            expect_json=False,
        )

        self.assertEqual(200, status)
        links = base64.b64decode(encoded).decode().splitlines()
        self.assertEqual(1, len(links))
        self.assertTrue(links[0].startswith("socks5://admin:secret@127.0.0.1:7920#JP_exit-01_"))

    def test_subscription_socks5_format_uses_reality_public_address_not_request_host(self):
        self.manager.set_slot_ready("exit-01")
        manifest = Path(self.tempdir.name) / "public-nodes.json"
        manifest.write_text(
            json.dumps({
                "version": 1,
                "nodes": [{
                    "slot_id": "exit-01",
                    "address": "153.121.38.245",
                    "port": 8443,
                    "uuid": "11111111-1111-1111-1111-111111111111",
                    "sni": "addons.mozilla.org",
                    "public_key": "abcdefghijklmnopqrstuvwxyzABCDEFGH1234567_",
                    "short_id": "aabbccddeeff0011",
                }],
            }),
            encoding="utf-8",
        )
        self.server.reality_nodes_file = manifest
        status, data = self.request("/api/data")
        token = data["mySubToken"]

        request = urllib.request.Request(
            f"{self.base}/api/sub?user={data['mySubUser']}&token={token}&format=socks5",
            headers={"Host": "vp.alibb123.ccwu.cc"},
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            links = base64.b64decode(response.read()).decode().splitlines()

        self.assertEqual(1, len(links))
        self.assertIn("@153.121.38.245:7920#JP_exit-01_", links[0])
        self.assertNotIn("@vp.alibb123.ccwu.cc:7920", links[0])

    def test_socks5_text_routes_require_subscription_token(self):
        self.manager.set_slot_ready("exit-01")
        status, data = self.request("/api/data")
        token = data["mySubToken"]

        status, body = self.request("/socks5.txt", authenticated=False, expect_json=False)
        self.assertEqual(404, status)
        self.assertIn("subscription not found", body)

        status, body = self.request(
            f"/socks5.txt?user={data['mySubUser']}&token={token}",
            expect_json=False,
        )
        self.assertEqual(200, status)
        self.assertIn("socks5://admin:secret@127.0.0.1:7920#JP_exit-01_", body)

        status, encoded = self.request(
            f"/socks5-b64.txt?user={data['mySubUser']}&token={token}",
            expect_json=False,
        )
        self.assertEqual(200, status)
        self.assertEqual(body, base64.b64decode(encoded).decode())

    def test_socks5_json_route_exports_current_proxies(self):
        self.manager.set_slot_ready("exit-01")
        content = (
            "socks5://198.51.100.20:1080#good%20jp\n"
            "socks5://proxy-user:proxy-pass@198.51.100.21:1081#Singapore"
        )
        with patch("vps.local_api.fetch_subscription_text", return_value=content):
            status, _ = self.request(
                "/api/thirdparty",
                method="POST",
                body={"name": "json-export", "url": "https://subscription.example.com/socks"},
            )
            self.assertEqual(200, status)
        status, data = self.request("/api/data")
        token = data["mySubToken"]

        status, denied = self.request("/socks5.json", authenticated=False)
        self.assertEqual(404, status)
        self.assertEqual("not_found", denied["code"])

        status, exported = self.request(
            f"/socks5.json?user={data['mySubUser']}&token={token}",
        )
        self.assertEqual(200, status)
        self.assertRegex(exported["exported_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertEqual([], exported["accounts"])
        self.assertEqual(3, len(exported["proxies"]))

        by_key = {proxy["proxy_key"]: proxy for proxy in exported["proxies"]}
        local = by_key["socks5|127.0.0.1|7920|admin|secret"]
        self.assertEqual("JP_exit-01_ready", local["name"])
        self.assertEqual("active", local["status"])
        self.assertEqual("none", local["fallback_mode"])

        anonymous = by_key["socks5|198.51.100.20|1080||"]
        self.assertEqual("good jp", anonymous["name"])
        self.assertNotIn("username", anonymous)
        self.assertNotIn("password", anonymous)

        authenticated = by_key["socks5|198.51.100.21|1081|proxy-user|proxy-pass"]
        self.assertEqual("proxy-user", authenticated["username"])
        self.assertEqual("proxy-pass", authenticated["password"])

    def test_subscription_socks5_format_excludes_non_socks_thirdparty_nodes(self):
        self.manager.set_slot_ready("exit-01")
        content = (
            "vless://11111111-1111-1111-1111-111111111111@vpn.example.com:443#Tokyo\n"
            "socks5://tpuser:tppass@relay.example.com:15080#TP-Relay"
        )
        with patch("vps.local_api.fetch_subscription_text", return_value=content):
            status, _ = self.request(
                "/api/thirdparty",
                method="POST",
                body={"name": "sub1", "url": "https://subscription.example.com/profile"},
            )
            self.assertEqual(200, status)
        status, data = self.request("/api/data")
        token = data["mySubToken"]

        status, encoded = self.request(
            f"/api/sub?user={data['mySubUser']}&token={token}&format=socks5",
            expect_json=False,
        )

        self.assertEqual(200, status)
        links = base64.b64decode(encoded).decode().splitlines()
        self.assertEqual(2, len(links))
        self.assertTrue(all(link.startswith("socks5://") for link in links))
        joined = "\n".join(links)
        self.assertNotIn("vpn.example.com", joined)
        self.assertIn("socks5://tpuser:tppass@relay.example.com:15080#TP-Relay", joined)

    def test_subscription_excludes_store_ready_slot_without_listener(self):
        self.manager.set_slot_ready("exit-01", listener_ready=False)
        status, data = self.request("/api/data")
        token = data["mySubToken"]

        status, encoded = self.request(f"/api/sub?user={data['mySubUser']}&token={token}", expect_json=False)

        self.assertEqual(200, status)
        self.assertEqual("", base64.b64decode(encoded).decode())

    def test_subscription_clash_format_includes_only_ready_listener_local_exits(self):
        self.manager.set_slot_ready("exit-01")
        status, data = self.request("/api/data")
        self.assertEqual(200, status)
        token = data["mySubToken"]

        status, body = self.request(f"/api/sub?user={data['mySubUser']}&token={token}&format=clash", expect_json=False)

        self.assertEqual(200, status)
        self.assertIn("type: socks5", body)
        self.assertIn('server: "127.0.0.1"', body)
        self.assertIn("port: 7920", body)
        self.assertIn("exit-01", body)

    def test_subscription_endpoint_formats(self):
        self.manager.set_slot_ready("exit-01")
        self.store.set_runtime(
            "exit-01",
            state="ready",
            entry_ip="198.51.100.1",
            egress_ip="203.0.113.1",
            current_node={"ip": "203.0.113.1", "country": "CA", "source": "vpngate"},
        )
        status, data = self.request("/api/data")
        self.assertEqual(200, status)
        self.assertEqual("admin", data["mySubUser"])
        token = data["mySubToken"]
        user = data["mySubUser"]
        token_owner = next(item for item in data["users"] if item["sub_token"] == token)
        self.assertEqual(user, token_owner["username"])

        # sing-box format
        status, content_type, body = self.request_text_with_content_type(
            f"/api/sub?user={user}&token={token}&format=sing-box"
        )
        self.assertEqual(200, status)
        self.assertEqual("application/json", content_type)
        sb_json = json.loads(body)
        self.assertIn("outbounds", sb_json)
        self.assertNotIn("dns", {outbound["type"] for outbound in sb_json["outbounds"]})
        local_socks = next(outbound for outbound in sb_json["outbounds"] if outbound["type"] == "socks")
        self.assertEqual("127.0.0.1", local_socks["server"])
        self.assertEqual(7920, local_socks["server_port"])
        known_tags = {outbound["tag"] for outbound in sb_json["outbounds"]}
        for outbound in sb_json["outbounds"]:
            if outbound["type"] in {"selector", "urltest"}:
                self.assertTrue(set(outbound["outbounds"]) <= known_tags)

        # v2ray and shadowrocket format
        for fmt in ["v2ray", "shadowrocket"]:
            status, content_type, encoded = self.request_text_with_content_type(
                f"/api/sub?user={user}&token={token}&format={fmt}"
            )
            self.assertEqual(200, status)
            self.assertEqual("text/plain", content_type)
            links = base64.b64decode(encoded).decode("utf-8").splitlines()
            self.assertEqual(1, len(links))
            self.assertTrue(links[0].startswith("socks5://admin:secret@127.0.0.1:7920#"))

        # clash-meta follows the cs-pa layout: fixed groups, no country buckets.
        status, content_type, body = self.request_text_with_content_type(
            f"/api/sub?user={user}&token={token}&format=clash-meta"
        )
        self.assertEqual(200, status)
        self.assertEqual("text/yaml", content_type)
        self.assertIn("mixed-port: 7890", body)
        self.assertIn('  - name: "🚀 节点选择"', body)
        self.assertIn('  - name: "⚡ 自动选择"', body)
        self.assertIn('  - name: "🏠 住宅自动"', body)
        self.assertIn('  - name: "🧠 Claude"', body)
        self.assertIn('  - name: "🇨🇳 中国流量"', body)
        self.assertNotIn('  - name: "🇨🇦 CA"', body)
        self.assertNotIn('  - name: "🇯🇵 JP"', body)
        self.assertNotIn('  - name: "🇰🇷 KR"', body)
        rocket_start = body.index('  - name: "🚀 节点选择"')
        rocket_end = body.index("\n  - name:", rocket_start + 1)
        self.assertIn('      - "CA未知·RESI·exit-01"', body[rocket_start:rocket_end])
        self.assertIn("proxies:", body)

        proxy_section, group_section = body.split("\nproxy-groups:\n", 1)
        group_section = group_section.split("\nrules:\n", 1)[0]

        def yaml_name(raw: str) -> str:
            raw = raw.strip()
            return json.loads(raw) if raw.startswith('"') else raw

        proxy_names = {
            yaml_name(match.group(1))
            for match in re.finditer(r"^  - name: (.+)$", proxy_section, re.MULTILINE)
        }
        group_matches = list(re.finditer(r"^  - name: (.+)$", group_section, re.MULTILINE))
        group_names = {yaml_name(match.group(1)) for match in group_matches}
        self.assertEqual(len(group_names), len(group_matches))
        for index, match in enumerate(group_matches):
            end = group_matches[index + 1].start() if index + 1 < len(group_matches) else len(group_section)
            group_block = group_section[match.start():end]
            references = [yaml_name(item) for item in re.findall(r"^      - (.+)$", group_block, re.MULTILINE)]
            self.assertTrue(set(references) <= proxy_names | group_names | {"DIRECT"})

    def test_subscription_accepts_token_only_for_default_user(self):
        content = "vless://11111111-1111-1111-1111-111111111111@vpn.example.com:443#Tokyo"
        with patch("vps.local_api.fetch_subscription_text", return_value=content):
            status, _ = self.request(
                "/api/thirdparty",
                method="POST",
                body={"name": "sub1", "url": "https://subscription.example.com/profile"},
            )
        self.assertEqual(200, status)

        status, data = self.request("/api/data")
        self.assertEqual(200, status)
        token = data["mySubToken"]

        status, encoded = self.request(f"/api/sub?token={token}", expect_json=False)
        self.assertEqual(200, status)
        links = base64.b64decode(encoded).decode()
        self.assertIn("vless://11111111-1111-1111-1111-111111111111@vpn.example.com:443", links)

        status, body = self.request(f"/api/sub?token=bad-token", expect_json=True)
        self.assertEqual(404, status)

    def test_subscription_user_parameter_is_not_hardcoded(self):
        self.server.username = "panel-user"
        status, data = self.request("/api/data")
        self.assertEqual(200, status)
        self.assertEqual("panel-user", data["mySubUser"])
        token = data["mySubToken"]

        status, _ = self.request(
            f"/api/sub?user={data['mySubUser']}&token={token}",
            expect_json=False,
        )
        self.assertEqual(200, status)
        status, body = self.request(
            f"/api/sub?user=admin&token={token}",
            expect_json=True,
        )
        self.assertEqual(404, status)
        self.assertEqual("not_found", body["code"])

    def test_subscription_formats_include_enabled_thirdparty_nodes(self):
        content = "\n".join((
            "vless://11111111-1111-1111-1111-111111111111@reality.example.com:443"
            "?encryption=none&security=reality&sni=www.example.com&pbk=public-key&sid=abcd#TP Reality",
            "socks5://tp-user:tp-pass@socks.example.com:1080#TP SOCKS",
        ))
        with patch("vps.local_api.fetch_subscription_text", return_value=content):
            status, created = self.request(
                "/api/thirdparty",
                method="POST",
                body={"name": "mixed", "url": "https://subscription.example.com/mixed"},
            )
        self.assertEqual(200, status)
        self.assertEqual(2, created["parsedCount"])

        status, data = self.request("/api/data")
        self.assertEqual(200, status)
        user = data["mySubUser"]
        token = data["mySubToken"]

        status, body = self.request(
            f"/api/sub?user={user}&token={token}&format=sing-box",
            expect_json=False,
        )
        self.assertEqual(200, status)
        config = json.loads(body)
        servers = {outbound.get("server") for outbound in config["outbounds"]}
        self.assertIn("reality.example.com", servers)
        self.assertIn("socks.example.com", servers)
        reality = next(outbound for outbound in config["outbounds"] if outbound.get("server") == "reality.example.com")
        self.assertTrue(reality["tls"]["reality"]["enabled"])
        socks = next(outbound for outbound in config["outbounds"] if outbound.get("server") == "socks.example.com")
        self.assertEqual("tp-user", socks["username"])
        self.assertEqual("tp-pass", socks["password"])

        status, encoded = self.request(
            f"/api/sub?user={user}&token={token}&format=shadowrocket",
            expect_json=False,
        )
        self.assertEqual(200, status)
        links = base64.b64decode(encoded).decode("utf-8").splitlines()
        self.assertEqual(2, len(links))
        self.assertTrue(any(link.startswith("vless://") for link in links))
        self.assertTrue(any(link.startswith("socks5://tp-user:tp-pass@socks.example.com:1080#") for link in links))

    def test_reality_clash_subscription_uses_actual_country_isp_and_egress_ip(self):
        self.manager.set_slot_ready("exit-03")
        self.store.set_runtime(
            "exit-03",
            state="ready",
            entry_ip="203.0.113.30",
            egress_ip="203.0.113.30",
            current_node={"ip": "203.0.113.30", "country": "JP", "source": "vpngate"},
            check_result={
                "residential": {
                    "raw": {
                        "geo": {"country": "Unknown", "country_code": "Unknown", "city": "Unknown"},
                        "isp": {"org": "KDDI CORPORATION", "flag": "residential"},
                    }
                }
            },
        )
        manifest = Path(self.tempdir.name) / "public-nodes.json"
        manifest.write_text(
            json.dumps({
                "version": 1,
                "nodes": [{
                    "slot_id": "exit-03",
                    "address": "153.121.38.245",
                    "port": 8445,
                    "uuid": "11111111-1111-1111-1111-111111111111",
                    "sni": "addons.mozilla.org",
                    "public_key": "abcdefghijklmnopqrstuvwxyzABCDEFGH1234567_",
                    "short_id": "aabbccddeeff0011",
                }],
            }),
            encoding="utf-8",
        )
        self.server.reality_nodes_file = manifest
        status, data = self.request("/api/data")
        token = data["mySubToken"]

        status, body = self.request(f"/api/sub?user={data['mySubUser']}&token={token}&format=clash", expect_json=False)

        self.assertEqual(200, status)
        self.assertIn('name: "JP住宅·KDDI·exit-03"', body)
        self.assertIn("type: vless", body)
        self.assertIn('server: "153.121.38.245"', body)
        self.assertIn("port: 8445", body)
        self.assertIn("flow: \"xtls-rprx-vision\"", body)
        self.assertIn("reality-opts:", body)
        self.assertNotIn("type: socks5", body)
        self.assertNotIn("ANY_exit-03_ready", body)
        self.assertIn('  - name: "🏠 住宅自动"\n    type: url-test', body)
        self.assertNotIn("type: relay", body)
        chain_proxy_name = "JP住宅·KDDI·exit-03·链式"
        chain_proxy_start = body.index(f'  - name: "{chain_proxy_name}"')
        chain_proxy_block = body[chain_proxy_start:body.index("\nproxy-groups:", chain_proxy_start)]
        self.assertIn('dialer-proxy: "⚡ 自动选择"', chain_proxy_block)
        self.assertIn(
            '  - name: "VLESS-REALITY-链式"\n    type: select\n'
            f'    proxies:\n      - "{chain_proxy_name}"',
            body,
        )
        rocket_start = body.index('  - name: "🚀 节点选择"')
        rocket_block = body[rocket_start:body.index("\n  - name:", rocket_start + 1)]
        self.assertIn('      - "VLESS-REALITY-链式"', rocket_block)

        status, encoded = self.request(f"/api/sub?user={data['mySubUser']}&token={token}", expect_json=False)
        links = base64.b64decode(encoded).decode()
        self.assertIn("vless://11111111-1111-1111-1111-111111111111@153.121.38.245:8445", links)
        self.assertIn("JP-%E6%97%A5%E6%9C%AC%20%7C%20%E4%BD%8F%E5%AE%85IP%20%7C%20KDDI%20%7C%20203.0.113.30%20%7C%20exit-03", links)
        self.assertNotIn("socks5://", links)

    def test_connectivity_only_exit_34_joins_residential_group_without_chain(self):
        self.store.initialize(slot_count=34)
        self.manager.set_slot_ready("exit-34")
        self.store.set_runtime(
            "exit-34",
            state="ready",
            entry_ip="198.51.100.34",
            egress_ip="203.0.113.34",
            current_node={"ip": "198.51.100.34", "country": "US", "source": "vpngate"},
            check_result={
                "residential": {
                    "status": "skipped",
                    "validation_mode": "connectivity_only",
                    "egress_type": "unverified",
                    "egress_type_label": "未验证IP",
                    "is_residential": False,
                },
                "targets": {"accepted": True},
            },
        )
        manifest = Path(self.tempdir.name) / "public-nodes.json"
        manifest.write_text(
            json.dumps({
                "version": 1,
                "nodes": [{
                    "slot_id": "exit-34",
                    "address": "153.121.38.245",
                    "port": 8477,
                    "uuid": "44444444-4444-4444-4444-444444444444",
                    "sni": "addons.mozilla.org",
                    "public_key": "abcdefghijklmnopqrstuvwxyzABCDEFGH1234567_",
                    "short_id": "aabbccddeeff0011",
                }],
            }),
            encoding="utf-8",
        )
        self.server.reality_nodes_file = manifest
        status, data = self.request("/api/data")
        token = data["mySubToken"]

        status, body = self.request(
            f"/api/sub?user={data['mySubUser']}&token={token}&format=clash",
            expect_json=False,
        )

        self.assertEqual(200, status)
        node_name = "US未验证·RESI·exit-34"
        self.assertIn(f'name: "{node_name}"', body)
        residential_start = body.index('  - name: "🏠 住宅自动"')
        residential_block = body[residential_start:body.index("\n  - name:", residential_start + 1)]
        self.assertIn(f'      - "{node_name}"', residential_block)
        self.assertNotIn(f'{node_name}·链式', body)

        manifest.write_text(
            json.dumps({
                "version": 1,
                "nodes": [{
                    "slot_id": "exit-35",
                    "address": "153.121.38.245",
                    "port": 8478,
                    "uuid": "55555555-5555-5555-5555-555555555555",
                    "sni": "addons.mozilla.org",
                    "public_key": "abcdefghijklmnopqrstuvwxyzABCDEFGH1234567_",
                    "short_id": "aabbccddeeff0011",
                }],
            }),
            encoding="utf-8",
        )
        status, body = self.request(
            f"/api/sub?user={data['mySubUser']}&token={token}&format=clash",
            expect_json=False,
        )
        self.assertEqual(200, status)
        self.assertNotIn("exit-35", body)

    def test_reality_clash_subscription_exposes_direct_and_cloudflare_entries(self):
        self.manager.set_slot_ready("exit-01")
        manifest = Path(self.tempdir.name) / "public-nodes.json"
        manifest.write_text(
            json.dumps({
                "version": 1,
                "nodes": [
                    {
                        "slot_id": "exit-01",
                        "address": "153.121.38.245",
                        "port": 8443,
                        "uuid": "11111111-1111-1111-1111-111111111111",
                        "sni": "addons.mozilla.org",
                        "public_key": "abcdefghijklmnopqrstuvwxyzABCDEFGH1234567_",
                        "short_id": "aabbccddeeff0011",
                    },
                    {
                        "slot_id": "tr-01",
                        "address": "153.121.38.245",
                        "port": 8501,
                        "uuid": "22222222-2222-2222-2222-222222222222",
                        "sni": "addons.mozilla.org",
                        "public_key": "abcdefghijklmnopqrstuvwxyzABCDEFGH1234567_",
                        "short_id": "1122334455667788",
                    },
                ],
            }),
            encoding="utf-8",
        )
        self.server.reality_nodes_file = manifest
        status, data = self.request("/api/data")
        token = data["mySubToken"]
        bridge = {
            "name": "bridge-01",
            "protocol": "Hysteria2",
            "address": "bridge.example.com",
            "port": 443,
            "password": "secret",
            "sni": "bridge.example.com",
        }

        with patch("vps.local_api.load_bridge_nodes", return_value=[bridge]):
            status, body = self.request(
                f"/api/sub?user={data['mySubUser']}&token={token}&format=clash",
                expect_json=False,
            )

        self.assertEqual(200, status)
        direct_name = "JP未知·RESI·exit-01"
        chain_name = "TR-土耳其 | ProxyScrape | tr-01 | 链式"
        direct_start = body.index(f'  - name: "{direct_name}"')
        chain_start = body.index(f'  - name: "{chain_name}"')
        direct_block = body[direct_start:chain_start]
        chain_block = body[chain_start:body.index("\nproxy-groups:", chain_start)]
        self.assertNotIn("dialer-proxy:", direct_block)
        self.assertIn('dialer-proxy: "⚡ 自动选择"', chain_block)
        self.assertEqual(1, body.count("dialer-proxy:"))
        self.assertNotIn("链式节点", body)
        self.assertNotIn('  - name: PROXY', body)
        rocket_start = body.index('  - name: "🚀 节点选择"')
        rocket_block = body[rocket_start:body.index("\n  - name:", rocket_start + 1)]
        self.assertIn(f'      - "{direct_name}"', rocket_block)
        self.assertIn(f'      - "{chain_name}"', rocket_block)

    def test_subscription_excludes_disabled_local_exit_socks5_nodes(self):
        self.request("/api/local/exits/exit-01/disable", method="POST", body={})
        status, data = self.request("/api/data")
        self.assertEqual(200, status)
        token = data["mySubToken"]

        status, encoded = self.request(f"/api/sub?user={data['mySubUser']}&token={token}", expect_json=False)

        self.assertEqual(200, status)
        links = base64.b64decode(encoded).decode()
        self.assertNotIn(":7920#JP_exit-01_", links)

    def test_proxy_switch_delegates_to_explicit_slot_redial(self):
        status, result = self.request("/api/proxy/switch", method="POST", body={"slot_id": "exit-01"})
        self.assertEqual(202, status)
        self.assertTrue(result["accepted"])
        self.assertIn(("redial", "exit-01"), self.manager.actions)

    def test_proxy_switch_accepts_unambiguous_legacy_port_mapping(self):
        status, result = self.request("/api/proxy/switch", method="POST", body={"port": 7921})
        self.assertEqual(202, status)
        self.assertTrue(result["accepted"])
        self.assertIn(("redial", "exit-02"), self.manager.actions)

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

    def test_probe_detail_returns_current_slot_and_check_history(self):
        self.store.set_runtime(
            "exit-01",
            state="ready",
            egress_ip="203.0.113.9",
            check_result={"targets": {"accepted": True}},
        )
        generation = self.store.get_slot("exit-01").generation
        self.store.append_check_result(
            "exit-01",
            generation,
            {"egress_ip": "203.0.113.9", "accepted": True},
        )

        status, body = self.request("/api/probe/detail?id=exit-01")

        self.assertEqual(200, status)
        self.assertEqual("exit-01", body["id"])
        self.assertEqual("203.0.113.9", body["egress_ip"])
        self.assertEqual({"targets": {"accepted": True}}, body["check_result"])
        self.assertEqual(1, len(body["check_history"]))
        self.assertEqual("203.0.113.9", body["check_history"][0]["result"]["egress_ip"])

    def test_probe_detail_returns_not_found_for_unknown_local_probe(self):
        status, body = self.request("/api/probe/detail?id=missing")

        self.assertEqual(404, status)
        self.assertEqual("not_found", body["code"])

    def test_probe_display_metadata_round_trips_without_replacing_slot_state(self):
        update_status, updated = self.request(
            "/api/probe/admin/server",
            method="PUT",
            body={
                "id": "exit-01",
                "name": "Tokyo residential",
                "server_group": "Japan",
                "is_hidden": "true",
                "price": "10USD/year",
                "expire_date": "2027-01-01",
                "bandwidth": "1Gbps",
                "traffic_limit": "1TB/month",
                "reset_day": "15",
            },
        )
        admin_status, admin = self.request("/api/probe/admin/data")
        detail_status, detail = self.request("/api/probe/detail?id=exit-01")

        self.assertEqual(200, update_status)
        self.assertEqual("Tokyo residential", updated["name"])
        self.assertEqual(200, admin_status)
        self.assertEqual(24, len(admin["servers"]))
        self.assertEqual("Tokyo residential", admin["servers"][0]["name"])
        self.assertEqual("Japan", admin["servers"][0]["server_group"])
        self.assertEqual("idle", admin["servers"][0]["state"])
        self.assertEqual(200, detail_status)
        self.assertEqual("Tokyo residential", detail["name"])
        self.assertEqual("exit-01", detail["id"])

    def test_reset_probe_display_metadata_keeps_slot_and_restores_defaults(self):
        self.request(
            "/api/probe/admin/server",
            method="PUT",
            body={"id": "exit-01", "name": "Custom", "server_group": "Custom group"},
        )

        reset_status, reset = self.request("/api/probe/admin/server?id=exit-01", method="DELETE")
        admin_status, admin = self.request("/api/probe/admin/data")
        detail_status, detail = self.request("/api/probe/detail?id=exit-01")

        self.assertEqual(200, reset_status)
        self.assertTrue(reset["success"])
        self.assertEqual(200, admin_status)
        self.assertEqual(24, len(admin["servers"]))
        self.assertEqual("exit-01", admin["servers"][0]["name"])
        self.assertEqual(200, detail_status)
        self.assertEqual("exit-01", detail["name"])

    def test_probe_display_metadata_rejects_unknown_slot(self):
        status, body = self.request(
            "/api/probe/admin/server",
            method="PUT",
            body={"id": "exit-99", "name": "Unknown"},
        )

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

    @patch("vps.local_api.set_additional_credentials")
    def test_user_password_change_updates_admin_proxy_without_replacing_gateway_credentials(self, set_additional_credentials):
        status, body = self.request("/api/user/password", method="PUT", body={"password": "newpass123"})
        self.assertEqual(200, status)
        self.assertTrue(body["success"])
        set_additional_credentials.assert_called_once_with([("admin", "newpass123")])
        stored = self.store.get_user("admin")
        self.assertIsNotNone(stored)
        expected_hash = LocalAPIHandler._hash_password("newpass123")
        self.assertEqual(expected_hash, stored["password"])

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
