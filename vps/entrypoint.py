from __future__ import annotations

import os
import signal
import threading
from pathlib import Path

from .exit_manager import ExitManager
from .local_api import LocalAPIServer
from .proxy_server import set_credentials
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
    proxy_user = management_user
    proxy_password = management_password

    store = LocalStore(database)
    store.initialize()
    workspace.mkdir(parents=True, exist_ok=True)
    auth_file = workspace / "auth.txt"
    auth_file.write_text("vpn\nvpn\n", encoding="utf-8")
    auth_file.chmod(0o600)
    set_credentials(proxy_user, proxy_password)
    manager = ExitManager(store, workspace=workspace)
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
