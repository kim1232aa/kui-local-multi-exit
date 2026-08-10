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

        def open_url(request, timeout, server_hostname=None):
            attempted.append((request.full_url, request.headers.get("Host")))
            return FakeResponse()

        with patch.dict(os.environ, {"KUI_FETCH_PROXY": ""}, clear=False), patch.object(
            vpngate, "resolve_ipv4_endpoints", return_value=list(endpoints)
        ), patch.object(vpngate, "open_direct_url", side_effect=open_url):
            nodes = vpngate.fetch_nodes()

        self.assertEqual([], nodes)
        self.assertEqual(
            [("https://199.59.150.12/api/iphone/", "www.vpngate.net")],
            attempted,
        )

    def test_endpoint_https_handler_keeps_origin_hostname_for_tls(self):
        class Result:
            def __init__(self):
                self.value = "ok"

        captured = {}
        handler = vpngate._EndpointHTTPSHandler("www.vpngate.net")

        def do_open(connection_class, request, **kwargs):
            with patch.object(vpngate, "_EndpointHTTPSConnection") as connection:
                connection_class("130.158.75.35", check_hostname=True)
            captured["call"] = connection.call_args
            captured["request_host"] = request.headers.get("Host")
            return Result()

        with patch.object(handler, "do_open", side_effect=do_open):
            request = vpngate.build_endpoint_request("130.158.75.35", vpngate.API_URL)
            response = handler.https_open(request)

        self.assertEqual("ok", response.value)
        args, kwargs = captured["call"]
        self.assertEqual(("130.158.75.35",), args)
        self.assertEqual("www.vpngate.net", kwargs["server_hostname"])
        self.assertNotIn("check_hostname", kwargs)
        self.assertEqual("www.vpngate.net", captured["request_host"])

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

        with patch.dict(os.environ, {"KUI_FETCH_PROXY": ""}, clear=False), patch.object(
            vpngate, "resolve_ipv4_endpoints", return_value=["199.59.150.12"]
        ), patch.object(vpngate, "open_direct_url", return_value=TextResponse()):
            nodes = vpngate.fetch_nodes()

        self.assertEqual(1, len(nodes))
        self.assertEqual("203.0.113.9", nodes[0]["ip"])
        self.assertEqual("JP", nodes[0]["country"])
        self.assertEqual(12, nodes[0]["ping"])
        self.assertEqual(100, nodes[0]["score"])

    def test_fetch_nodes_deduplicates_duplicate_endpoint_ips(self):
        encoded = __import__("base64").b64encode(b"client\ndev tun\nremote 203.0.113.9 1194\n").decode()
        csv_body = (
            "*vpn_servers\n"
            "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
            f"jp1,203.0.113.9,100,50,3,Japan,JP,1,99,10,100,Free,Test,OK,{encoded}\n"
            f"jp2,203.0.113.9,90,10,3,Japan,JP,1,99,10,100,Free,Test,OK,{encoded}\n"
        )

        class TextResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return csv_body.encode()

        with patch.dict(os.environ, {"KUI_FETCH_PROXY": ""}, clear=False), patch.object(
            vpngate, "resolve_ipv4_endpoints", return_value=["199.59.150.12"]
        ), patch.object(vpngate, "open_direct_url", return_value=TextResponse()):
            nodes = vpngate.fetch_nodes()

        self.assertEqual(1, len(nodes))
        self.assertEqual(10, nodes[0]["ping"])

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

        with patch.dict(os.environ, {"KUI_FETCH_PROXY": ""}, clear=False), patch.object(
            vpngate, "resolve_ipv4_endpoints", return_value=["199.59.150.12"]
        ), patch.object(vpngate, "open_direct_url", return_value=TextResponse()):
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

    def test_probe_targets_records_every_target_without_early_success_return(self):
        target_codes = {
            vpngate.DEFAULT_STREAM_URL: "204",
            "https://www.google.com/": "301",
            "https://chatgpt.com": "403",
            "https://cn.tradingview.com": "500",
            "https://claude.ai": "000",
        }

        class Result:
            returncode = 0
            stderr = ""

        def run(command, **_kwargs):
            result = Result()
            result.stdout = target_codes[command[-1]]
            if result.stdout == "000":
                result.returncode = 28
            return result

        report = vpngate.probe_targets(
            "tun0",
            tuple(target_codes)[1:],
            run=run,
        )

        self.assertFalse(report["accepted"])
        self.assertTrue(report["base_ok"])
        self.assertFalse(report["custom_ok"])
        self.assertEqual(list(target_codes), [attempt["url"] for attempt in report["attempts"]])
        self.assertEqual(
            ["204", "301", "403", "500", "000"],
            [attempt["code"] for attempt in report["attempts"]],
        )
        self.assertEqual("explicit_response", report["attempts"][2]["classification"])
        self.assertEqual("redirect", report["attempts"][1]["classification"])
        self.assertEqual("timeout", report["attempts"][4]["classification"])

    def test_probe_targets_uses_marked_doh_instead_of_system_dns(self):
        commands = []

        class Result:
            returncode = 0
            stdout = "204"
            stderr = ""

        def run(command, **_kwargs):
            commands.append(command)
            return Result()

        report = vpngate.probe_targets(
            "tun0",
            ("https://www.google.com/",),
            run=run,
        )

        self.assertTrue(report["accepted"])
        for command in commands:
            self.assertEqual("https://cloudflare-dns.com/dns-query", command[command.index("--doh-url") + 1])
            self.assertIn("cloudflare-dns.com:443:1.1.1.1", command)
            self.assertEqual("tun0", command[command.index("--interface") + 1])

    def test_probe_targets_requires_every_custom_target_success(self):
        codes = {
            vpngate.DEFAULT_STREAM_URL: "204",
            "https://www.google.com/": "200",
            "https://chatgpt.com": "403",
            "https://cn.tradingview.com": "000",
            "https://claude.ai": "403",
        }

        class Result:
            stderr = ""

        def run(command, **_kwargs):
            result = Result()
            result.stdout = codes[command[-1]]
            result.returncode = 0 if result.stdout != "000" else 28
            return result

        report = vpngate.probe_targets(
            "tun0",
            tuple(codes)[1:],
            run=run,
        )

        self.assertFalse(report["accepted"])
        self.assertFalse(report["custom_ok"])

    def test_probe_targets_accepts_safe_redirect_when_followed_target_responds(self):
        commands = []

        def run(command, **_kwargs):
            class Result:
                returncode = 0
                stdout = "204" if command[-1] == vpngate.DEFAULT_STREAM_URL else "200"
                stderr = ""

            commands.append(command)
            return Result()

        report = vpngate.probe_targets(
            "tun0",
            ("https://www.google.com/",),
            run=run,
        )

        self.assertTrue(report["accepted"])
        self.assertIn("--location", commands[0])
        self.assertEqual("20", commands[0][commands[0].index("--max-redirs") + 1])

    def test_probe_targets_requires_base_and_one_custom_success(self):
        scenarios = [
            ({vpngate.DEFAULT_STREAM_URL: "200", "https://chatgpt.com": "403"}, False),
            ({vpngate.DEFAULT_STREAM_URL: "204", "https://chatgpt.com": "500"}, False),
            ({vpngate.DEFAULT_STREAM_URL: "204", "https://chatgpt.com": "407"}, False),
        ]

        for codes, expected in scenarios:
            with self.subTest(codes=codes):
                class Result:
                    returncode = 0
                    stderr = ""

                def run(command, **_kwargs):
                    result = Result()
                    result.stdout = codes[command[-1]]
                    return result

                report = vpngate.probe_targets("tun0", ("https://chatgpt.com",), run=run)
                self.assertEqual(expected, report["accepted"])

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
