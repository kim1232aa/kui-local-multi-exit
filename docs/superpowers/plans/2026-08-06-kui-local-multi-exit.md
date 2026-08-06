# K-UI Local Multi-Exit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve K-UI's existing VPNGate and residential-check workflow while exposing twelve independently configurable local proxy exits from one Docker container.

**Architecture:** Replace the Cloudflare control plane with a local Python HTTP API backed by SQLite. Refactor the current `tun_main`/`tun_backup` singleton flow into twelve `ExitSlot` instances, each owning one OpenVPN process, TUN interface, route table, health lifecycle, and SOCKS5/HTTP listener.

**Tech Stack:** Python 3.12 standard library, OpenVPN, iproute2, curl, SQLite, K-UI HTML/JavaScript, Docker Compose, unittest.

## Global Constraints

- Preserve existing K-UI VPNGate parsing, OpenVPN sanitization, TestISP, streaming checks, proxy authentication, and ordinary K-UI functions unless multi-exit requires adaptation.
- Exactly 12 persistent exit slots; country and proxy port are editable per slot.
- One OpenVPN tunnel per slot; three consecutive failures automatically disable only that slot.
- One container managed by Docker Compose; `/dev/net/tun` and `NET_ADMIN` are required.
- Management UI is publicly bindable but always authenticated; management and proxy credentials are distinct.
- No subagents for implementation, per user instruction.

---

### Task 1: Local slot persistence and state model

**Files:**
- Create: `vps/models.py`
- Create: `vps/store.py`
- Create: `tests/test_store.py`

**Interfaces:**
- Produces: `ExitSlotConfig`, `ExitSlotSnapshot`, `LocalStore.initialize()`, `LocalStore.list_slots()`, `LocalStore.update_slot()` and `LocalStore.record_event()`.

- [ ] Write unit tests that create a temporary SQLite database, assert twelve default slots, update one slot country/port without changing other slots, and persist automatic-disable state.
- [ ] Run `python -m unittest tests.test_store -v`; expect failures because modules do not exist.
- [ ] Implement immutable configuration/runtime snapshot dataclasses and transactional SQLite schema initialization.
- [ ] Run `python -m unittest tests.test_store -v`; expect all tests to pass.

### Task 2: Multi-listener proxy server

**Files:**
- Modify: `vps/proxy_server.py`
- Create: `tests/test_proxy_server.py`

**Interfaces:**
- Consumes: slot ID, listener port, and TUN interface name.
- Produces: `ProxyListener(slot_id, host, port, interface)`, `start()`, `stop()`, `ready`, and interface-bound `create_connection(address, interface)`.

- [ ] Add failing tests for two listeners with different interface context, independent lifecycle, and existing SOCKS5/HTTP auth behavior.
- [ ] Run `python -m unittest tests.test_proxy_server -v`; expect missing multi-listener API failures.
- [ ] Refactor global `ACTIVE_BIND` and `listener_ready` into per-listener state while retaining protocol parsing and credential validation.
- [ ] Run proxy tests and compile with `python -m py_compile vps/proxy_server.py`.

### Task 3: Slot-owned routing and OpenVPN lifecycle

**Files:**
- Create: `vps/routing.py`
- Create: `vps/exit_manager.py`
- Create: `tests/test_routing.py`
- Create: `tests/test_exit_manager.py`

**Interfaces:**
- Consumes: `ExitSlotConfig`, sanitized VPNGate node dictionaries, and `ProxyListener`.
- Produces: `RouteManager.install(slot, endpoint_ip)`, `RouteManager.cleanup(slot)`, `ExitManager.start_slot(id)`, `stop_slot(id)`, `redial_slot(id)`, `snapshot()`.

- [ ] Write command-recorder tests asserting unique `tun0..tun11`, route tables `200..211`, endpoint bypass routes, and idempotent cleanup.
- [ ] Write lifecycle tests asserting operations touch one slot only, stale generations cannot commit, and three failures persist disabled state.
- [ ] Run both test modules; expect import failures.
- [ ] Implement command construction and subprocess injection in `routing.py` without executing shell strings.
- [ ] Extract existing OpenVPN sanitization, TestISP, streaming checks, node penalty and health behavior from `lite_manager.py` into slot-scoped lifecycle methods.
- [ ] Run routing/manager tests and compile all Python modules.

### Task 4: Local API and authentication

**Files:**
- Create: `vps/local_api.py`
- Create: `tests/test_local_api.py`

**Interfaces:**
- Consumes: `LocalStore` and `ExitManager`.
- Produces: authenticated endpoints `/api/local/status`, `/api/local/exits`, `/api/local/exits/{id}`, `/redial`, `/enable`, `/api/local/events`, `/healthz`.

- [ ] Add HTTP contract tests for auth failure, slot listing, valid updates, invalid country/port, redial, re-enable, and error JSON.
- [ ] Run API tests; expect missing module failure.
- [ ] Implement a threaded standard-library HTTP server with constant-time Basic Auth verification and stable JSON errors.
- [ ] Run API tests and compile the module.

### Task 5: Compose entrypoint and startup recovery

**Files:**
- Create: `Dockerfile`
- Create: `compose.yaml`
- Create: `vps/entrypoint.py`
- Create: `vps/requirements.txt`
- Create: `tests/test_entrypoint.py`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: SQLite path and credentials from environment variables.
- Produces: one process supervisor that initializes storage, cleans stale routes, starts API/UI, then starts enabled slots.

- [ ] Add tests asserting startup order, disabled slots are not started, and shutdown cleans every active slot.
- [ ] Implement the entrypoint and health check.
- [ ] Add a single-container image with OpenVPN, iproute2 and curl; map twelve proxy ports plus the management port in Compose.
- [ ] Run unit tests, `docker compose config`, and image build.

### Task 6: K-UI multi-exit screen

**Files:**
- Modify: `index.html`
- Create: `tests/test_dashboard.py`

**Interfaces:**
- Consumes: local API contracts from Task 4.
- Produces: authenticated multi-exit dashboard cards and slot actions while preserving existing K-UI sections.

- [ ] Add HTML contract tests asserting twelve-slot view hooks, country/port controls, redial, enable/disable, current egress, original residential result and failure display.
- [ ] Run dashboard tests; expect missing hooks.
- [ ] Add local API client and multi-exit view using existing K-UI visual primitives; keep accepted operations visually distinct from completed tunnel state.
- [ ] Run dashboard and API contract tests.

### Task 7: End-to-end multi-exit validation

**Files:**
- Create: `tests/integration/test_multi_exit.py`
- Modify: `README.md`

**Interfaces:**
- Validates all prior tasks through Docker Compose and real proxy ports.

- [ ] Add an opt-in integration test that queries `/api/local/exits`, connects through each ready SOCKS5 port, calls an IP echo endpoint, and compares the result with the slot snapshot.
- [ ] Document local deployment, credentials, required kernel capabilities, slot editing, automatic disable behavior, SSH/reverse-proxy guidance, and exact verification commands.
- [ ] Run `python -m unittest discover -s tests -v`.
- [ ] Run `docker compose build` and `docker compose up -d`.
- [ ] Validate two slots first, then six, then all twelve; record any country without available VPNGate nodes as unavailable rather than fabricating a result.
- [ ] Run per-port `curl --socks5-hostname` checks, management auth checks, country-change isolation, redial isolation, three-failure disable, manual enable, and container restart recovery.
- [ ] Stop the validation stack without deleting persisted user data.
