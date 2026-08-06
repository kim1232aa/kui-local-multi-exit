import socket
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


if __name__ == "__main__":
    unittest.main()
