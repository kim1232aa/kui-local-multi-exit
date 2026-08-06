import os
import socket
import unittest
from unittest.mock import patch

from vps import vpngate


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return b""


class VPNGateFetchTest(unittest.TestCase):
    def test_url_opener_ignores_process_proxy_environment(self):
        with patch.dict(
            os.environ,
            {
                "HTTP_PROXY": "http://127.0.0.1:9",
                "HTTPS_PROXY": "http://127.0.0.1:9",
                "ALL_PROXY": "socks5://127.0.0.1:9",
            },
            clear=False,
        ):
            opener = vpngate.direct_url_opener()

        proxy_handlers = [handler for handler in opener.handlers if handler.__class__.__name__ == "ProxyHandler"]
        self.assertEqual([], proxy_handlers)

    def test_fetch_nodes_uses_explicit_control_plane_proxy(self):
        attempted = []

        class Result:
            returncode = 0
            stdout = ""
            stderr = ""

        def run(command, **kwargs):
            attempted.append((command, kwargs))
            return Result()

        with patch.dict(
            os.environ,
            {"KUI_FETCH_PROXY": "socks5://host.docker.internal:7896"},
            clear=False,
        ), patch.object(vpngate.subprocess, "run", side_effect=run), patch.object(
            vpngate, "resolve_ipv4_endpoints", side_effect=AssertionError("direct path must not run")
        ):
            nodes = vpngate.fetch_nodes()

        self.assertEqual([], nodes)
        command, kwargs = attempted[0]
        self.assertIn("--proxy", command)
        self.assertIn("socks5h://host.docker.internal:7896", command)
        self.assertNotIn("socks5://host.docker.internal:7896", command)
        self.assertIn(vpngate.API_URL, command)
        self.assertTrue(kwargs["capture_output"])
        self.assertTrue(kwargs["text"])

    def test_fetch_nodes_retries_all_resolved_ipv4_endpoints(self):
        endpoints = iter(["199.59.150.12", "168.143.171.93"])
        attempted = []

        def open_url(request, timeout):
            attempted.append((request.full_url, request.headers.get("Host")))
            return FakeResponse()

        with patch.object(vpngate, "resolve_ipv4_endpoints", return_value=list(endpoints)), patch.object(
            vpngate, "open_direct_url", side_effect=open_url
        ):
            nodes = vpngate.fetch_nodes()

        self.assertEqual([], nodes)
        self.assertEqual(
            [("https://199.59.150.12/api/iphone/", "www.vpngate.net")],
            attempted,
        )

    def test_fetch_nodes_handles_hash_header_line_like_kui(self):
        # K-UI 会去掉首行开头的 #；当前项目只跳过 * 行，需对齐
        csv_body = (
            "*vpn_servers\n"
            "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
            "jp1,203.0.113.9,100,12,3,Japan,JP,1,99,10,100,Free,Test,OK,"
            + __import__("base64").b64encode(b"client\ndev tun\nremote 203.0.113.9 1194\n").decode()
            + "\n"
        )

        class TextResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return csv_body.encode()

        with patch.object(vpngate, "resolve_ipv4_endpoints", return_value=["199.59.150.12"]), patch.object(
            vpngate, "open_direct_url", return_value=TextResponse()
        ):
            nodes = vpngate.fetch_nodes()

        self.assertEqual(1, len(nodes))
        self.assertEqual("203.0.113.9", nodes[0]["ip"])
        self.assertEqual("JP", nodes[0]["country"])
        self.assertEqual(12, nodes[0]["ping"])
        self.assertEqual(100, nodes[0]["score"])

    def test_node_pool_replace_preserves_worst_ping_like_kui(self):
        # K-UI 刷新快照时保留惩罚性 ping（取 max），防止坏节点回到前列
        pool = vpngate.NodePool()
        pool.replace(
            [
                {"ip": "203.0.113.9", "country": "JP", "ping": 500, "score": 10, "config": ""},
            ]
        )
        pool.replace(
            [
                {"ip": "203.0.113.9", "country": "JP", "ping": 1, "score": 100, "config": ""},
            ]
        )

        nodes = pool.list_nodes("ANY")
        self.assertEqual(1, len(nodes))
        self.assertEqual(500, nodes[0]["ping"])

    def test_fetch_countries_parses_dynamic_country_column(self):
        csv_body = (
            "*vpn_servers\n"
            "jp1,203.0.113.9,100,12,3,Japan,JP,1,99,10,100,Free,Test,OK,AAAA\n"
            "us1,198.51.100.7,90,30,2,United States,US,1,99,10,100,Free,Test,OK,AAAA\n"
            "xx1,192.0.2.1,80,40,2,Unknown,xx,1,99,10,100,Free,Test,OK,AAAA\n"
        )

        class TextResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return csv_body.encode()

        with patch.object(vpngate, "resolve_ipv4_endpoints", return_value=["199.59.150.12"]), patch.object(
            vpngate, "open_direct_url", return_value=TextResponse()
        ):
            countries = vpngate.fetch_countries()

        self.assertEqual(["JP", "US"], countries)

    def test_residential_lookup_failure_is_not_classified_as_residential(self):
        class BrokenOpener:
            def open(self, *_args, **_kwargs):
                raise OSError("lookup unavailable")

        with patch.object(vpngate, "direct_url_opener", return_value=BrokenOpener()):
            residential, detail = vpngate.check_residential("203.0.113.9")

        self.assertFalse(residential)
        self.assertEqual("unknown", detail["status"])
        self.assertIn("lookup unavailable", detail["error"])

    def test_non_residential_or_unknown_testisp_flag_is_not_classified_as_residential(self):
        for flag in ("isp", "unknown", ""):
            with self.subTest(flag=flag):
                report = {
                    "geo": {"is_native": True},
                    "isp": {"flag": flag, "type": "broadband", "warning": ""},
                }
                class Response:
                    def __enter__(self):
                        return self

                    def __exit__(self, *_args):
                        return False

                    def read(self):
                        return __import__("json").dumps(report).encode()

                class Opener:
                    def open(self, *_args, **_kwargs):
                        return Response()

                with patch.object(vpngate, "direct_url_opener", return_value=Opener()):
                    residential, detail = vpngate.check_residential("203.0.113.9")

                self.assertFalse(residential)
                self.assertFalse(detail["is_residential"])

        class Result:
            returncode = 0
            stdout = ""

        for code in ("301", "302", "500", "000"):
            Result.stdout = code
            ok, _detail = vpngate.check_streaming(
                "tun0",
                run=lambda *_args, **_kwargs: Result(),
                urls=("https://chatgpt.com",),
            )
            self.assertFalse(ok, code)

    def test_default_generate_204_probe_requires_exact_204(self):
        class Result:
            returncode = 0
            stdout = "200"

        ok, detail = vpngate.check_streaming("tun0", run=lambda *_args, **_kwargs: Result(), urls=(
            "https://www.gstatic.com/generate_204",
        ))

        self.assertFalse(ok)
        self.assertEqual("200", detail["attempts"][0]["code"])

    def test_custom_probe_accepts_2xx_and_explicit_4xx_but_not_redirect_or_407(self):
        expected = {
            "200": True,
            "204": True,
            "403": True,
            "404": True,
            "301": False,
            "407": False,
            "500": False,
            "000": False,
        }

        for code, accepted in expected.items():
            with self.subTest(code=code):
                class Result:
                    returncode = 0 if code != "000" else 28
                    stdout = code

                ok, _detail = vpngate.check_streaming(
                    "tun0",
                    run=lambda *_args, **_kwargs: Result(),
                    urls=("https://chatgpt.com",),
                )
                self.assertEqual(accepted, ok)


if __name__ == "__main__":
    unittest.main()
