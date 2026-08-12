from __future__ import annotations

import os
import signal
import threading
from pathlib import Path

from .bridge_nodes import start_background_refresh
from .exit_manager import ExitManager
from .internal_proxy import load_or_create_internal_proxy_credentials
from .local_api import LocalAPIServer
from .proxy_server import configure_connection_limit, set_additional_credentials, set_credentials
from .runtime_profile import resolve_runtime_profile
from .store import LocalStore


PROXY_ENVIRONMENT = {
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
}


def clear_proxy_environment() -> None:
    for name in PROXY_ENVIRONMENT:
        os.environ.pop(name, None)


class Application:
    def __init__(self, manager: ExitManager, server: LocalAPIServer):
        self.manager = manager
        self.server = server
        self._shutdown_lock = threading.Lock()
        self._stopped = False

    def run(self) -> None:
        self.manager.initialize()
        self.server.serve_forever()

    def shutdown(self) -> None:
        with self._shutdown_lock:
            if self._stopped:
                return
            self._stopped = True
            self.manager.shutdown()
            self.server.shutdown()
            self.server.server_close()


def build_application() -> Application:
    clear_proxy_environment()
    workspace = Path(os.environ.get("KUI_WORKSPACE", "/opt/kui-local"))
    database = Path(os.environ.get("KUI_DATABASE", str(workspace / "state.db")))
    web_root = Path(os.environ.get("KUI_WEB_ROOT", "/app/web"))
    management_host = os.environ.get("KUI_MANAGEMENT_HOST", "0.0.0.0")
    management_port = int(os.environ.get("KUI_MANAGEMENT_PORT", "8080"))
    management_user = os.environ.get("KUI_MANAGEMENT_USER", "admin")
    management_password = os.environ.get("KUI_MANAGEMENT_PASSWORD", "")
    profile = resolve_runtime_profile()
    store = LocalStore(database)
    store.initialize(slot_count=profile.slot_count)
    workspace.mkdir(parents=True, exist_ok=True)
    auth_file = workspace / "auth.txt"
    auth_file.write_text("vpn\nvpn\n", encoding="utf-8")
    auth_file.chmod(0o600)
    internal_proxy_user, internal_proxy_password = load_or_create_internal_proxy_credentials(workspace)
    set_credentials(internal_proxy_user, internal_proxy_password)
    set_additional_credentials([(management_user, management_password)])
    configure_connection_limit(profile.max_connections)
    manager = ExitManager(
        store,
        workspace=workspace,
        slot_count=profile.slot_count,
        dial_workers=profile.dial_workers,
    )

    manual_urls = [u.strip() for u in (os.environ.get("KUI_BRIDGE_NODES", "") or "").split(",") if u.strip()]
    subscription_urls = [u.strip() for u in (os.environ.get("KUI_BRIDGE_SUB_URLS", "") or "").split(",") if u.strip()]
    if subscription_urls:
        refresh_interval = int(os.environ.get("KUI_BRIDGE_REFRESH_INTERVAL", "300"))
        enable_speed_test = os.environ.get("KUI_BRIDGE_SPEED_TEST", "") == "1"
        top_n = int(os.environ.get("KUI_BRIDGE_TOP_N", "16"))
        start_background_refresh(
            interval=refresh_interval,
            manual_urls=manual_urls,
            subscription_urls=subscription_urls,
            enable_speed_test=enable_speed_test,
            top_n=top_n,
            max_workers=profile.dial_workers,
        )

    server = LocalAPIServer(
        (management_host, management_port),
        store=store,
        manager=manager,
        web_root=web_root,
        username=management_user,
        password=management_password,
    )
    return Application(manager, server)


def main() -> None:
    application = build_application()

    def stop(_signum, _frame):
        threading.Thread(target=application.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        application.run()
    finally:
        application.shutdown()


if __name__ == "__main__":
    main()
