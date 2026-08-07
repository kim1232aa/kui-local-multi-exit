# K-UI Local Multi-Exit Rework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Repair the existing K-UI Local Multi-Exit implementation so every published proxy is a genuinely validated, isolated local exit and every retained K-UI management entry performs real local work rather than returning placeholders.

**Architecture:** Keep the single-container Python/SQLite/K-UI architecture, but make `ExitManager` the fail-closed owner of each slot generation, route, OpenVPN process, listener and validation result. Add persistent VPNGate/check history and focused local management services, then reconnect the existing front end to those concrete APIs and prove the result with unit, container, browser and real SOCKS5 integration checks.

**Tech Stack:** Python 3.12 standard library, SQLite, OpenVPN, iproute2, curl, Docker Compose, Vue-in-a-single-HTML dashboard, unittest.

## Global Constraints

- Independent repository: `https://github.com/kim1232aa/kui-local-multi-exit`, branch `main`.
- Exactly 12 persistent slots: `exit-01..exit-12`, TUN `tun0..tun11`, route tables/marks `200..211`, externally published ports limited to `7920..7931`.
- Management page and local management API remain login-free; no “系统准入”, no second management password flow.
- All 12 proxy listeners use one configured SOCKS5/HTTP username/password pair.
- Do not remove or hide original K-UI management sections; every visible action must have a real local API effect or a precise unsupported error, never a silent 200 or fixed empty placeholder.
- A slot becomes `ready` only after OpenVPN, routing, non-empty real egress IP, explicit TestISP residential classification, target probe policy, listener bind, and final generation check all pass.
- Only `enabled && state == ready && listener_ready` slots may be published through extraction or subscriptions.
- `KUI_FETCH_PROXY` and `KUI_OPENVPN_SOCKS_PROXY` may use `socks5://host.docker.internal:7896`; generic proxy environment variables must not affect control or data plane.
- Public VPNGate scarcity may leave fewer than 12 ready slots; never duplicate or fabricate exits to reach 12.
- Implement test-first. Do not commit or push until the user explicitly asks for those Git mutations; local code/test edits are authorized by the active request.

---

## File Responsibility Map

- `vps/store.py`: transactional slot state, generation-guarded updates, VPNGate snapshots, check history, complete K-UI local records, Realm configuration.
- `vps/models.py`: immutable slot and persisted-record value objects.
- `vps/routing.py`: checked slot-specific policy-route installation and idempotent cleanup.
- `vps/proxy_server.py`: listener bind lifecycle, per-listener client tracking and marked outbound connections.
- `vps/vpngate.py`: VPNGate parsing, real egress detection, TestISP fail-closed classification and multi-target probe policy.
- `vps/exit_manager.py`: sole owner of slot lifecycle, generations, retries, route/process/listener cleanup and ready commit.
- `vps/local_api.py`: login-free local management contracts, ready-only publication, settings/statistics/probe/Realm APIs and full field round-trips.
- `vps/realm_manager.py`: local Realm configuration validation, process lifecycle and status.
- `vps/subscriptions.py`: parse/export symmetry for all accepted third-party protocols.
- `index.html`: existing K-UI sections wired to concrete local APIs and accurate asynchronous states.
- `compose.yaml`, `Dockerfile`, `.gitignore`, `README.md`, `README.local.md`: reproducible Linux Docker deployment and truthful operational guidance.
- `tests/`: unit/contract coverage; `tests/integration/`: opt-in Docker and real-exit validation.

---

### Task 1: Generation-Guarded Persistence and VPNGate Snapshots

**Files:**
- Modify: `vps/models.py`
- Modify: `vps/store.py`
- Modify: `tests/test_store.py`

**Interfaces:**
- Produces: `LocalStore.set_runtime_if_generation(slot_id: str, generation: int, **values) -> ExitSlotSnapshot | None`
- Produces: `LocalStore.validate_slot_update(slot_id: str, *, country: str | None, proxy_port: int | None, enabled: bool | None) -> ExitSlotSnapshot`
- Produces: `LocalStore.replace_vpn_nodes(nodes: list[dict[str, Any]]) -> None`
- Produces: `LocalStore.load_vpn_nodes() -> list[dict[str, Any]]`
- Produces: `LocalStore.append_check_result(slot_id: str, generation: int, result: dict[str, Any]) -> None`

- [ ] **Step 1: Add failing tests for generation guards, fixed ports, snapshot recovery and runtime clearing**

```python
def test_stale_generation_cannot_write_runtime(self):
    current = self.store.get_slot("exit-01")
    self.store.update_slot("exit-01", country="CA")
    result = self.store.set_runtime_if_generation(
        "exit-01", current.generation, state="ready", egress_ip="203.0.113.9"
    )
    self.assertIsNone(result)
    self.assertNotEqual("ready", self.store.get_slot("exit-01").state)


def test_proxy_port_is_limited_to_published_range(self):
    with self.assertRaisesRegex(ValueError, "7920 through 7931"):
        self.store.validate_slot_update("exit-01", country=None, proxy_port=9001, enabled=None)


def test_vpngate_snapshot_survives_reopen(self):
    nodes = [{"ip": "198.51.100.1", "country": "JP", "ping": 22,
              "score": 100, "config": "proto tcp\n", "harvested_at": 1.0}]
    self.store.replace_vpn_nodes(nodes)
    reopened = LocalStore(self.db_path)
    reopened.initialize()
    self.assertEqual(nodes, reopened.load_vpn_nodes())


def test_record_failure_clears_current_runtime(self):
    self.store.set_runtime("exit-01", state="ready", entry_ip="198.51.100.1",
                           egress_ip="203.0.113.1", current_node={"ip": "198.51.100.1"},
                           check_result={"targets": []})
    failed = self.store.record_failure("exit-01", "lost tunnel")
    self.assertEqual("", failed.entry_ip)
    self.assertEqual("", failed.egress_ip)
    self.assertEqual({}, failed.current_node)
    self.assertEqual({}, failed.check_result)
```

- [ ] **Step 2: Run the store tests and verify the new assertions fail**

Run: `python3 -m unittest tests.test_store -v`

Expected: failures for missing snapshot/guard methods, port `9001` still accepted, and stale runtime fields retained.

- [ ] **Step 3: Add schema migrations and transactional methods**

Add tables:

```sql
CREATE TABLE IF NOT EXISTS vpn_nodes (
    ip TEXT PRIMARY KEY,
    country TEXT NOT NULL,
    ping INTEGER NOT NULL,
    score INTEGER NOT NULL,
    config TEXT NOT NULL,
    harvested_at REAL NOT NULL,
    penalty INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS check_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slot_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    result TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
```

Implement one internal slot-update validator. It accepts only `7920 <= proxy_port <= 7931`, verifies uniqueness before any runtime stop, and is reused by `validate_slot_update()` and `update_slot()`. Implement `set_runtime_if_generation()` as a single `UPDATE ... WHERE id = ? AND generation = ?`, returning `None` when `rowcount != 1`. Make `record_failure()` clear current runtime fields while preserving history in `events`/`check_results`.

- [ ] **Step 4: Run store tests**

Run: `python3 -m unittest tests.test_store -v`

Expected: all store tests pass.

- [ ] **Step 5: Run schema compatibility smoke test**

Run:

```bash
python3 - <<'PY'
from pathlib import Path
from tempfile import TemporaryDirectory
from vps.store import LocalStore
with TemporaryDirectory() as d:
    s = LocalStore(Path(d) / 'state.db')
    s.initialize(); s.initialize()
    assert len(s.list_slots()) == 12
    assert s.load_vpn_nodes() == []
print('schema-ok')
PY
```

Expected: `schema-ok`.

---

### Task 2: Checked Routing and Synchronous Listener Readiness

**Files:**
- Modify: `vps/routing.py`
- Modify: `vps/proxy_server.py`
- Modify: `tests/test_routing.py`
- Modify: `tests/test_proxy_server.py`

**Interfaces:**
- Produces: `RouteCommandError(RuntimeError)` with command, return code and stderr.
- Produces: `ProxyListener.start(timeout: float = 3.0) -> None`, which returns only after bind success or raises.
- Produces: `ProxyListener.is_ready() -> bool`.

- [ ] **Step 1: Add a failing routing-command test**

```python
def test_install_raises_when_required_command_fails(self):
    class FailingRecorder(CommandRecorder):
        def __call__(self, command, **kwargs):
            result = super().__call__(command, **kwargs)
            if command[:3] == ["ip", "route", "add"]:
                result.returncode = 2
                result.stderr = "RTNETLINK answers: Operation not permitted"
            return result
    routing = RouteManager(run=FailingRecorder())
    with self.assertRaisesRegex(RuntimeError, "Operation not permitted"):
        routing.install(self.first, "198.51.100.1", "172.18.0.1", "eth0")
```

- [ ] **Step 2: Add a real port-conflict listener test**

```python
def test_listener_start_raises_when_port_is_occupied(self):
    occupied = socket.socket()
    occupied.bind(("127.0.0.1", 0))
    occupied.listen(1)
    port = occupied.getsockname()[1]
    listener = proxy_server.ProxyListener("exit-01", "127.0.0.1", port, "tun0", 200)
    try:
        with self.assertRaises(OSError):
            listener.start(timeout=1)
        self.assertFalse(listener.is_ready())
    finally:
        listener.stop()
        occupied.close()
```

Add another test that accepts a real client, calls `stop()`, and verifies the listener tracks and closes the accepted client sockets. Assert two listeners have distinct semaphores/client sets.

- [ ] **Step 3: Run the focused tests and verify failure**

Run: `python3 -m unittest tests.test_routing tests.test_proxy_server -v`

Expected: routing failure is ignored and listener start returns without surfacing bind failure.

- [ ] **Step 4: Implement checked route installation**

`RouteManager._execute(command, *, allow_missing=False)` must inspect `returncode`. Cleanup may ignore known missing-rule messages (`No such file`, `Cannot find device`, `FIB table does not exist`); installation never ignores non-zero status. If installation fails after partial success, call `cleanup(slot)` and re-raise.

- [ ] **Step 5: Implement listener startup handshake and per-listener resources**

Add `self._startup_error`, `self._clients`, `self._clients_lock`, and a per-listener bounded semaphore. `serve_forever()` records bind exceptions and always sets a startup-complete event. `start()` waits for startup completion, stops on timeout, and raises the captured exception unless `ready` is set. `stop()` closes servers and tracked clients before joining.

- [ ] **Step 6: Run focused tests**

Run: `python3 -m unittest tests.test_routing tests.test_proxy_server -v`

Expected: all pass.

---

### Task 3: Fail-Closed Slot Lifecycle and Multi-Target Probes

**Files:**
- Modify: `vps/vpngate.py`
- Modify: `vps/exit_manager.py`
- Modify: `tests/test_vpngate.py`
- Modify: `tests/test_exit_manager.py`

**Interfaces:**
- Produces: `probe_targets(interface: str, urls: Sequence[str], run=...) -> dict[str, Any]`
- Produces: `ExitManager.listener_ready(slot_id: str) -> bool`
- Consumes: `LocalStore.set_runtime_if_generation()` and synchronous `ProxyListener.start()`.

- [ ] **Step 1: Add failing egress, probe and listener tests**

Add tests:

```python
def test_empty_egress_probe_fails_without_endpoint_fallback(self):
    # Stub OpenVPN initialization and routing success, but detect_egress returns "".
    # Assert _handle_connection_failure receives "real egress IP unavailable" and
    # check_residential is never called.


def test_commit_ready_rejects_listener_bind_failure(self):
    class FailingListener(FakeListener):
        def start(self, timeout=3):
            raise OSError("address in use")
    # Assert commit_ready raises/fails and store never becomes ready.


def test_failure_racing_commit_cannot_restore_ready(self):
    # Block listener.start(), call fail_slot() to increment generation, release start,
    # then assert commit_ready returns False and final state remains failed/disabled.


def test_manual_preferred_udp_node_is_rejected_with_socks_proxy(self):
    # Preferred UDP node and a valid TCP fallback exist; assert reserve returns TCP node.
```

In `tests/test_vpngate.py`, add exact per-target results for the four defaults, asserting 2xx and non-407 4xx are explicit responses, 3xx/5xx/407/timeout fail, and no early return drops later target details.

- [ ] **Step 2: Run focused tests and verify failure**

Run: `python3 -m unittest tests.test_vpngate tests.test_exit_manager -v`

Expected: endpoint fallback, early-return probe behavior and listener/generation races fail the tests.

- [ ] **Step 3: Implement complete target probing**

Replace single-success `check_streaming()` semantics with a result containing every attempt:

```python
{
  "base_ok": True,
  "custom_ok": True,
  "accepted": True,
  "attempts": [
    {"url": "...", "code": 403, "accepted": True,
     "classification": "explicit_response", "elapsed_ms": 312, "error": ""}
  ]
}
```

Always run the base `https://www.gstatic.com/generate_204` probe plus configured targets. Accept slot validation only when `base_ok` and at least one custom target has an accepted explicit response. Keep each target result for UI display.

- [ ] **Step 4: Make `_connect_worker()` fail closed at each boundary**

- Load probe URLs and revision from settings before dial.
- After OpenVPN init, route install, egress detect, residential check and target probe, call a helper that verifies enabled/generation/probe revision.
- Reject empty egress IP with `RuntimeError("real egress IP unavailable")`.
- Use the same `_node_eligible()` helper for manual and automatic selection.
- Persist check history before final ready commit.
- Call synchronous listener start, then final generation-guarded store update.
- On any exception, stop the newly created listener and clean route/process/runtime fields.

- [ ] **Step 5: Make stop/fail/redial invalidate the worker first**

Introduce a store method that increments generation without altering validated configuration. `stop_slot()`, `redial_slot()`, `connect_slot()`, `disable_slot()` and `fail_slot()` call it before releasing the runtime lock. A worker that fails to stop within two seconds leaves an explicit `failed` state; it cannot be reused as the next worker.

- [ ] **Step 6: Run focused and full lifecycle tests**

Run:

```bash
python3 -m unittest tests.test_vpngate tests.test_exit_manager -v
python3 -m unittest tests.test_store tests.test_routing tests.test_proxy_server -v
```

Expected: all pass.

---

### Task 4: Ready-Only Publication and Transactional Slot API

**Files:**
- Modify: `vps/local_api.py`
- Modify: `tests/test_local_api.py`
- Modify: `tests/test_dashboard.py`

**Interfaces:**
- Produces: `_publishable_slots() -> list[dict[str, Any]]`.
- Produces: `PUT /api/local/exits/{id}` with validation-before-stop semantics.
- Produces: `POST /api/proxy/switch` requiring `slot_id` (legacy `port` mapping allowed, ignored `ip` removed).

- [ ] **Step 1: Replace the incorrect publication expectations**

Change idle-slot tests from “12 links exist” to:

```python
def test_idle_slots_are_not_published(self):
    status, body = self.request("/api/proxy/proxies", expect_json=False)
    self.assertEqual(200, status)
    self.assertEqual("", body.strip())


def test_only_ready_listener_slots_are_published(self):
    self.manager.set_slot_ready("exit-01", listener_ready=True)
    status, body = self.request("/api/proxy/proxies", expect_json=False)
    self.assertIn(":7920#", body)
    self.assertNotIn(":7921#", body)
```

Add equivalent ordinary and Clash subscription tests. Add a test where the store slot is `ready` but manager reports listener not ready; it must not publish.

- [ ] **Step 2: Add failing transactional update and switch-target tests**

```python
def test_invalid_update_does_not_stop_ready_slot(self):
    self.manager.set_slot_ready("exit-01", listener_ready=True)
    status, _ = self.request("/api/local/exits/exit-01", method="PUT",
                             body={"proxy_port": 7921})
    self.assertEqual(400, status)
    self.assertNotIn(("stop", "exit-01"), self.manager.actions)


def test_switch_requires_explicit_slot(self):
    status, body = self.request("/api/proxy/switch", method="POST", body={"ip": "10.0.0.8"})
    self.assertEqual(400, status)
    self.assertEqual("slot_id is required", body["error"])
```

- [ ] **Step 3: Run API tests and verify failure**

Run: `python3 -m unittest tests.test_local_api tests.test_dashboard -v`

- [ ] **Step 4: Implement one publishable-slot source**

Use manager snapshots enriched with `listener_ready`. Filter exactly:

```python
slot["enabled"] and slot["state"] == "ready" and slot["listener_ready"]
```

Use this helper for `/api/proxy/proxies`, `_local_subscription_links()`, `_local_clash_proxies()`, proxy status counts and extraction output. Failed/idle slots remain visible only in management status.

- [ ] **Step 5: Validate update before stopping**

Call `store.validate_slot_update()` first. If validation succeeds and the effective config changes, invalidate/stop only that slot, persist the update, and start it if enabled. Validation errors return 400 without runtime actions.

- [ ] **Step 6: Remove dead login contracts without adding another password**

Delete `/api/login`, token issuance/validation paths and the unused `_authenticated()` flow. Keep `/healthz`, assets and all management endpoints login-free. Update tests to assert no login endpoint or frontend login state exists; retain subscription token checks because those protect generated subscription URLs, not management login.

- [ ] **Step 7: Run API/dashboard tests**

Run: `python3 -m unittest tests.test_local_api tests.test_dashboard -v`

Expected: all pass.

---

### Task 5: Complete Local K-UI Data Contracts

**Files:**
- Modify: `vps/store.py`
- Modify: `vps/local_api.py`
- Modify: `vps/subscriptions.py`
- Modify: `tests/test_local_api.py`
- Modify: `tests/test_subscriptions.py`

**Interfaces:**
- Produces complete VPS fields: `egress_mode`, `proxy_mode`, `proxy_categories`, `egress_revision`, `egress_status`, `egress_applied_mode`, `egress_applied_revision`, `egress_error`, `egress_ip`.
- Produces complete node fields used by `index.html`: protocol endpoint, UUID/password, SNI, keys, transport and path/host settings.
- Produces parse/export symmetry or explicit import rejection.

- [ ] **Step 1: Add schema round-trip tests for all UI fields**

Build a representative Reality node and selective residential VPS payload. POST, GET, PUT and GET again; assert every submitted field is preserved and returned. Add a migration test opening an existing old schema and verifying `initialize()` adds columns without dropping rows.

- [ ] **Step 2: Add protocol symmetry tests**

For every protocol accepted by `parse_subscription()`, assert either:

```python
self.assertTrue(api._subscription_link(node) or api._clash_proxy(node))
```

or assert import returns `400 unsupported_protocol` before persistence. For SSR, implement full URI re-serialization if its parsed fields are complete; otherwise reject SSR explicitly at import so it cannot be counted then silently omitted.

- [ ] **Step 3: Run tests and verify current field loss**

Run: `python3 -m unittest tests.test_local_api tests.test_subscriptions -v`

- [ ] **Step 4: Add compatible SQLite migrations and CRUD mappings**

Add columns with `PRAGMA table_info` checks and `ALTER TABLE`. Expand `add_vps()`, `update_vps()`, `add_node()`, `update_node()` and API allowlists to use the exact frontend names. Never return 200 while silently dropping an input field; unknown fields receive `400 unsupported_field`.

- [ ] **Step 5: Implement revision/status semantics**

An egress update increments `egress_revision`, stores `pending`, maps the local server to a selected slot, and records either `applied` or `failed` based on actual local manager state. A stale result revision cannot overwrite a newer request.

- [ ] **Step 6: Run tests**

Run: `python3 -m unittest tests.test_local_api tests.test_subscriptions -v`

Expected: all pass.

---

### Task 6: Replace Statistics, Probe, Full Deploy and Realm Placeholders

**Files:**
- Create: `vps/realm_manager.py`
- Create: `tests/test_realm_manager.py`
- Modify: `vps/store.py`
- Modify: `vps/local_api.py`
- Modify: `Dockerfile`
- Modify: `tests/test_local_api.py`

**Interfaces:**
- Produces: `RealmManager.status()`, `configure(payload)`, `start()`, `stop()`.
- Produces: `GET /api/stats` from persisted events/check history.
- Produces: `GET /api/probe/public` and `/api/probe/admin/data` with 12 local slot records.
- Produces: `GET/PUT/POST /api/realm` local Realm contracts.
- Produces: local Full Deploy/maintenance command data in `/api/data` or a dedicated `/api/local/deploy-command`.

- [ ] **Step 1: Add failing non-placeholder API tests**

Assert `/api/stats` reflects a recorded connection/failure event; probe endpoints contain 12 servers with slot ID, state, egress IP, check result and updated time; Full Deploy data contains an executable `docker compose up -d --build` maintenance command and no `agent_token`/`agent_update`; Realm configure/start/status/stop persists configuration and reports real process state.

- [ ] **Step 2: Add Realm manager unit tests**

Inject `subprocess.Popen` and validate generated arguments without shell strings. Test invalid listen/remote endpoints, process start failure, idempotent stop and restart recovery. The manager must report `unavailable` with a precise error if the binary is missing, not a success placeholder.

- [ ] **Step 3: Run focused tests and verify failure**

Run: `python3 -m unittest tests.test_realm_manager tests.test_local_api -v`

- [ ] **Step 4: Implement local statistics and probe projection**

Use `events`, `check_results` and current slot snapshots to generate actual records. Empty history may produce empty time-series points, but `servers` must still contain the 12 current slots; it cannot be hardcoded `[]`.

- [ ] **Step 5: Implement local deployment command contract**

Return a command for this repository/container only. It must not install APK on Debian, request an agent token or call `/api/agent_update`. Include the repository URL, `.env` variables and `docker compose up -d --build` in structured fields so the UI can render and copy it.

- [ ] **Step 6: Implement Realm lifecycle**

Persist local Realm mappings in SQLite/settings, validate them, and run the bundled/installed Realm binary. Add the package/binary to `Dockerfile` using a pinned source/version already approved by project licensing; if distribution cannot be bundled reliably, expose a verified installation state and a concrete install action rather than claiming Realm is running.

- [ ] **Step 7: Run focused tests**

Run: `python3 -m unittest tests.test_realm_manager tests.test_local_api -v`

Expected: all pass.

---

### Task 7: Rewire Every Existing Dashboard Section

**Files:**
- Modify: `index.html`
- Modify: `tests/test_dashboard.py`
- Modify: `tests/test_local_api.py`

**Interfaces:**
- Consumes Tasks 4–6 API contracts.
- Produces browser-visible, actionable sections: servers/nodes, users, residential multi-exit, Realm, third-party services/subscriptions, settings and probe dashboard.

- [ ] **Step 1: Replace marker-only tests with behavior-contract assertions**

Add static assertions that forbidden dead contracts are absent:

```python
for forbidden in ("agent_token", "/api/agent_update", "请先刷新页面以签发独立 Agent Token",
                  "功能规划占位", "isLoggedIn = ref(true)", "Bearer local"):
    self.assertNotIn(forbidden, html)
```

Assert every visible action references an existing local endpoint. Add a small JavaScript extraction/fixture test for request bodies so `proxy_mode`, `proxy_categories`, full node fields and `slot_id` are submitted.

- [ ] **Step 2: Run dashboard tests and verify failure**

Run: `python3 -m unittest tests.test_dashboard -v`

- [ ] **Step 3: Rewire servers/nodes and egress controls**

Use complete Task 5 records. Display server egress status from returned revision/status fields. Save every node field and show API errors instead of success when unsupported.

- [ ] **Step 4: Replace Full Deploy and Realm placeholder UI**

Render the local deployment command returned by the API. Build Realm forms/status/action buttons against `/api/realm`. Keep both original navigation entries visible.

- [ ] **Step 5: Render truthful multi-target and publishability state**

Each slot card shows listener readiness, entry/egress IP, TestISP raw status, and each configured URL with code/classification/error. Use “目标明确应答 403” rather than “可正常使用”. Failed/idle slots show why they are not in subscriptions.

- [ ] **Step 6: Rewire statistics/probe and keep all other sections operational**

Use local probe records and check history. Verify users, third-party CRUD, settings and subscription protection still call their existing concrete endpoints after the rewrite.

- [ ] **Step 7: Run dashboard/API tests**

Run: `python3 -m unittest tests.test_dashboard tests.test_local_api -v`

Expected: all pass.

---

### Task 8: Docker, Control-Plane Proxy and Runtime File Hygiene

**Files:**
- Modify: `compose.yaml`
- Modify: `Dockerfile`
- Modify: `.gitignore`
- Modify: `vps/entrypoint.py`
- Modify: `vps/exit_manager.py`
- Modify: `README.local.md`
- Create: `tests/test_deployment_contract.py`

**Interfaces:**
- Compose consumes optional `KUI_FETCH_PROXY` and `KUI_OPENVPN_SOCKS_PROXY`.
- Linux containers resolve `host.docker.internal` through `host-gateway`.

- [ ] **Step 1: Add failing deployment-contract tests**

Parse `compose.yaml` as text/structured YAML already available in the environment and assert both `KUI_*` variables plus `host.docker.internal:host-gateway`. Assert `.gitignore` covers `*.ovpn`, `*.log`, `auth.txt`, `socks_auth.txt` and runtime config directories. Assert the fixed published port range matches store validation.

- [ ] **Step 2: Run deployment tests and verify failure**

Run: `python3 -m unittest tests.test_deployment_contract -v`

- [ ] **Step 3: Update Compose and runtime permissions**

Add:

```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
environment:
  KUI_FETCH_PROXY: ${KUI_FETCH_PROXY:-}
  KUI_OPENVPN_SOCKS_PROXY: ${KUI_OPENVPN_SOCKS_PROXY:-}
```

Write `.ovpn` and log files with mode `0600`. Continue clearing generic proxy environment variables in `entrypoint.py` while leaving the two explicit KUI variables intact.

- [ ] **Step 4: Update deployment documentation**

Document exact temporary proxy invocation:

```bash
export KUI_FETCH_PROXY='socks5://host.docker.internal:7896'
export KUI_OPENVPN_SOCKS_PROXY='socks5://host.docker.internal:7896'
docker compose up -d --build
```

State that container `healthy` only proves the management process is alive, not that any slot is ready.

- [ ] **Step 5: Run deployment checks**

Run:

```bash
python3 -m unittest tests.test_deployment_contract -v
KUI_MANAGEMENT_PASSWORD=test-only docker compose config --quiet
docker build --check .
```

Expected: all pass.

---

### Task 9: Real Integration Harness and Browser Acceptance

**Files:**
- Create: `tests/integration/test_multi_exit.py`
- Create: `tests/integration/README.md`
- Modify: `README.md`
- Modify: `README.local.md`

**Interfaces:**
- Opt-in environment: `KUI_INTEGRATION=1`, management URL, proxy credentials and target URLs.
- Produces a machine-readable report for every slot/target without fabricating unavailable exits.

- [ ] **Step 1: Write the opt-in integration test**

The test skips unless `KUI_INTEGRATION=1`. It fetches `/api/local/exits`, and for every ready slot:

```python
observed = curl_via_socks(slot["proxy_port"], "https://api.ipify.org")
self.assertEqual(slot["egress_ip"], observed)
```

It checks uniqueness for simultaneously ready slots, records Google/ChatGPT/TradingView/Claude status, and asserts non-ready slots are absent from `/api/proxy/proxies` and subscriptions. It must not require exactly 12 ready exits.

- [ ] **Step 2: Add lifecycle integration cases**

Exercise two slots first: redial one, verify the other listener/IP remains unchanged; change one country/port assignment; force three failures through a documented test hook or invalid candidate; manually enable; restart the container and verify persisted slot configuration and VPNGate snapshot.

- [ ] **Step 3: Run the full host test suite before rebuilding**

Run:

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q vps tests
```

Expected: all tests pass.

- [ ] **Step 4: Rebuild and run tests inside Python 3.12 image**

Run:

```bash
KUI_MANAGEMENT_PASSWORD="$KUI_MANAGEMENT_PASSWORD" \
KUI_FETCH_PROXY='socks5://host.docker.internal:7896' \
KUI_OPENVPN_SOCKS_PROXY='socks5://host.docker.internal:7896' \
docker compose build

docker run --rm --entrypoint python kui-local-multi-exit:latest \
  -m unittest discover -s /app/tests -v
```

Use the actual Compose image name from `docker compose images` if it differs.

- [ ] **Step 5: Start the stack and validate 2, then 6, then 12 slots**

Do not delete the named volume. Start/restart the app, wait for explicit API states, and run the integration test at each enabled-slot stage. Record unavailable countries/nodes as failures, not substitutes.

- [ ] **Step 6: Perform headless browser acceptance**

Use the project browser skill/agent-browser against `http://127.0.0.1:8080/`. Visit every navigation section and execute at least one reversible action in each: server/node create-edit-delete, user create-disable-delete, slot candidate selection/redial, Realm config/status, third-party import/disable/delete, settings save, probe view. Capture request/response evidence and ensure there is no login modal, empty placeholder or dead button.

- [ ] **Step 7: Run final verification**

Run:

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q vps tests
KUI_MANAGEMENT_PASSWORD=test-only docker compose config --quiet
git diff --check
git status --short --branch
```

Then compare every requirement in `docs/superpowers/specs/2026-08-07-kui-local-multi-exit-rework-design.md` against actual evidence. Do not claim completion if any visible K-UI action remains empty or any ready proxy lacks matching observed egress IP.
