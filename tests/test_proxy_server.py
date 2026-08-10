import socket
import time
import unittest
from unittest.mock import patch

from vps import proxy_server


class FakeSocket:
    def __init__(self, family=socket.AF_INET, socktype=socket.SOCK_STREAM, proto=0):
        self.family = family
        self.socktype = socktype
        self.proto = proto
        self.options = []
        self.connected = None
        self.closed = False

    def setsockopt(self, level, option, value):
        self.options.append((level, option, value))

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, address):
        self.connected = address

    def close(self):
        self.closed = True


class ProxyServerTest(unittest.TestCase):
    def test_create_connection_marks_requested_route(self):
        created = []

        def factory(family, socktype, proto=0):
            result = FakeSocket(family, socktype, proto)
            created.append(result)
            return result

        with patch.object(proxy_server, "resolve_host", return_value=["203.0.113.10"]), patch.object(
            proxy_server.socket, "socket", side_effect=factory
        ):
            connection = proxy_server.create_connection(("example.com", 443), 207, timeout=3)

        self.assertIs(connection, created[0])
        self.assertIn((socket.SOL_SOCKET, proxy_server.SO_MARK, 207), created[0].options)
        self.assertEqual(("203.0.113.10", 443), created[0].connected)

    def test_create_connection_uses_marked_doh_instead_of_system_dns(self):
        created = []

        def factory(family, socktype, proto=0):
            result = FakeSocket(family, socktype, proto)
            created.append(result)
            return result

        with patch.object(proxy_server, "resolve_host", return_value=["104.18.32.47"]) as resolver, patch.object(
            proxy_server.socket,
            "getaddrinfo",
            side_effect=AssertionError("system DNS must not resolve proxy targets"),
        ), patch.object(proxy_server.socket, "socket", side_effect=factory):
            connection = proxy_server.create_connection(("chatgpt.com", 443), 207, timeout=3)

        resolver.assert_called_once_with("chatgpt.com", 207, timeout=3)
        self.assertIs(connection, created[0])
        self.assertIn((socket.SOL_SOCKET, proxy_server.SO_MARK, 207), created[0].options)
        self.assertEqual(("104.18.32.47", 443), created[0].connected)

    def test_listener_instances_keep_independent_slot_configuration(self):
        first = proxy_server.ProxyListener("exit-01", "0.0.0.0", 7920, "tun0", 200)
        second = proxy_server.ProxyListener("exit-02", "0.0.0.0", 7921, "tun1", 201)

        self.assertEqual("tun0", first.interface)
        self.assertEqual("tun1", second.interface)
        self.assertEqual(200, first.mark)
        self.assertEqual(201, second.mark)
        self.assertEqual(7920, first.port)
        self.assertEqual(7921, second.port)
        self.assertIsNot(first.ready, second.ready)

    def test_stopping_one_listener_does_not_stop_another(self):
        first = proxy_server.ProxyListener("exit-01", "0.0.0.0", 7920, "tun0", 200)
        second = proxy_server.ProxyListener("exit-02", "0.0.0.0", 7921, "tun1", 201)
        first._stop.clear()
        second._stop.clear()

        first.stop()

        self.assertTrue(first._stop.is_set())
        self.assertFalse(second._stop.is_set())

    def test_credentials_can_be_changed_without_restarting_listeners(self):
        proxy_server.set_credentials("alice", "secret")
        first = proxy_server.ProxyListener("exit-01", "0.0.0.0", 7920, "tun0", 200)

        self.assertEqual(b"alice", proxy_server.PROXY_USER)
        self.assertEqual(b"secret", proxy_server.PROXY_PASS)
        self.assertEqual("exit-01", first.slot_id)

    def test_start_raises_when_listener_port_cannot_bind(self):
        occupied = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        occupied.bind(("127.0.0.1", 0))
        occupied.listen(1)
        listener = proxy_server.ProxyListener(
            "exit-01",
            "127.0.0.1",
            occupied.getsockname()[1],
            "tun0",
            200,
        )
        try:
            with self.assertRaises(OSError):
                listener.start()
        finally:
            listener.stop()
            occupied.close()

    def test_listener_connection_limits_are_independent(self):
        first = proxy_server.ProxyListener("exit-01", "0.0.0.0", 7920, "tun0", 200)
        second = proxy_server.ProxyListener("exit-02", "0.0.0.0", 7921, "tun1", 201)

        self.assertTrue(hasattr(first, "_connection_slots"))
        self.assertTrue(hasattr(second, "_connection_slots"))
        self.assertIsNot(first._connection_slots, second._connection_slots)
        self.assertTrue(hasattr(first, "_clients"))
        self.assertTrue(hasattr(second, "_clients"))
        self.assertIsNot(first._clients, second._clients)

    def test_stop_closes_tracked_accepted_clients(self):
        listener = proxy_server.ProxyListener("exit-01", "127.0.0.1", 0, "tun0", 200)
        listener.start()
        port = listener._servers[0].getsockname()[1]
        client = socket.create_connection(("127.0.0.1", port), timeout=1)
        try:
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline and not listener._clients:
                time.sleep(0.01)
            self.assertTrue(listener._clients)

            listener.stop()

            self.assertEqual(b"", client.recv(1))
            self.assertEqual(set(), listener._clients)
        finally:
            client.close()
            listener.stop()

    def test_udp_relay_uses_marked_shared_resolver(self):
        listener = proxy_server.ProxyListener("exit-01", "127.0.0.1", 7920, "tun0", 200)

        class StopAfterOne:
            def is_set(self):
                return False

        class FakeTCP:
            def settimeout(self, _timeout):
                pass

        class FakeUDP:
            def __init__(self):
                self.calls = 0
                self.sent = []
                self.closed = False

            def settimeout(self, _timeout):
                pass

            def recvfrom(self, _size):
                self.calls += 1
                if self.calls == 1:
                    packet = b"\x00\x00\x00\x03\x0bexample.com\x00\x35query"
                    return packet, ("127.0.0.1", 50000)
                raise KeyboardInterrupt

            def sendto(self, data, address):
                self.sent.append((data, address))

            def close(self):
                self.closed = True

        class FakeOutbound:
            def setsockopt(self, *_args):
                pass

            def settimeout(self, _timeout):
                pass

            def sendto(self, data, address):
                self.request = (data, address)

            def recvfrom(self, _size):
                return b"reply", ("203.0.113.53", 53)

            def close(self):
                pass

        udp = FakeUDP()
        listener._stop = StopAfterOne()
        with patch.object(proxy_server.select, "select", return_value=([], [], [])), patch.object(
            proxy_server, "resolve_host", return_value=["203.0.113.53"]
        ) as resolver, patch.object(proxy_server.socket, "socket", return_value=FakeOutbound()):
            with self.assertRaises(KeyboardInterrupt):
                listener._udp_relay(FakeTCP(), udp)

        resolver.assert_called_once_with("example.com", 200, timeout=5.0)
        self.assertTrue(udp.closed)
        self.assertEqual(("127.0.0.1", 50000), udp.sent[0][1])
        self.assertEqual(b"\x00\x00\x00\x01\xcb\x00\x71\x35\x00\x35reply", udp.sent[0][0])

    def test_udp_associate_binds_the_public_slot_port(self):
        proxy_server.set_credentials("alice", "secret")
        listener = proxy_server.ProxyListener("exit-01", "0.0.0.0", 7920, "tun0", 200)

        class FakeClient:
            def __init__(self):
                self.input = bytearray(
                    b"\x01\x02"  # one method: username/password
                    b"\x01\x05alice\x06secret"
                    b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"
                )
                self.sent = bytearray()

            def recv(self, size, *_args):
                result = bytes(self.input[:size])
                del self.input[:size]
                return result

            def sendall(self, data):
                self.sent.extend(data)

        class FakeUDP:
            def __init__(self):
                self.bound = None
                self.options = []

            def setsockopt(self, *args):
                self.options.append(args)

            def bind(self, address):
                self.bound = address

            def close(self):
                pass

        client = FakeClient()
        udp = FakeUDP()
        with patch.object(proxy_server.socket, "socket", return_value=udp), patch.object(
            listener, "_udp_relay", return_value=None
        ):
            listener._socks5_client(client)

        self.assertEqual(("0.0.0.0", 7920), udp.bound)
        self.assertNotIn((socket.SOL_SOCKET, proxy_server.SO_MARK, 200), udp.options)
        self.assertTrue(bytes(client.sent).endswith(b"\x05\x00\x00\x01\x00\x00\x00\x00\x1e\xf0"))

    def test_listener_reports_ready_only_while_bound(self):
        listener = proxy_server.ProxyListener("exit-01", "127.0.0.1", 0, "tun0", 200)

        self.assertFalse(listener.is_ready())
        listener.start()
        self.assertTrue(listener.is_ready())
        listener.stop()
        self.assertFalse(listener.is_ready())


if __name__ == "__main__":
    unittest.main()
