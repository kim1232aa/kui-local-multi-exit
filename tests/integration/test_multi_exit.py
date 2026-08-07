import json
import os
import subprocess
import unittest
import urllib.request


TARGET_URLS = {
    "https://www.google.com/",
    "https://chatgpt.com",
    "https://cn.tradingview.com",
    "https://claude.ai",
}


@unittest.skipUnless(os.environ.get("KUI_INTEGRATION") == "1", "set KUI_INTEGRATION=1 for live SOCKS5 checks")
class MultiExitIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_url = os.environ.get("KUI_BASE_URL", "http://127.0.0.1:8080").rstrip("/")
        cls.proxy_host = os.environ.get("KUI_PROXY_HOST", "127.0.0.1")
        cls.proxy_user = os.environ.get("KUI_PROXY_USER", "admin")
        cls.proxy_password = os.environ.get("KUI_PROXY_PASSWORD", "")
        cls.expected_ready = int(os.environ.get("KUI_EXPECT_READY_SLOTS", "0"))

    @classmethod
    def api_json(cls, path):
        with urllib.request.urlopen(cls.base_url + path, timeout=15) as response:
            return json.load(response)

    def test_ready_slots_have_real_unique_socks_egress_and_all_target_records(self):
        slots = self.api_json("/api/local/exits")["exits"]
        self.assertEqual(12, len(slots))
        ready = [slot for slot in slots if slot["enabled"] and slot["state"] == "ready" and slot["listener_ready"]]
        if self.expected_ready:
            self.assertEqual(self.expected_ready, len(ready))

        observed = {}
        for slot in ready:
            proxy = f"socks5h://{self.proxy_user}:{self.proxy_password}@{self.proxy_host}:{slot['proxy_port']}"
            result = subprocess.run(
                ["curl", "--fail", "--silent", "--show-error", "--max-time", "20", "--proxy", proxy, "https://api.ipify.org"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, f"{slot['id']}: {result.stderr}")
            actual = result.stdout.strip()
            self.assertEqual(slot["egress_ip"], actual, slot["id"])
            self.assertNotIn(actual, observed, f"{slot['id']} and {observed.get(actual)} share egress {actual}")
            observed[actual] = slot["id"]

            attempts = slot.get("check_result", {}).get("targets", {}).get("attempts", [])
            attempted_urls = {attempt.get("url") for attempt in attempts}
            self.assertTrue(TARGET_URLS.issubset(attempted_urls), f"{slot['id']} missing target records")
            target_attempts = [attempt for attempt in attempts if attempt.get("url") in TARGET_URLS]
            self.assertEqual(len(TARGET_URLS), len(target_attempts), f"{slot['id']} has duplicate or missing custom targets")
            self.assertTrue(all(attempt.get("accepted") for attempt in target_attempts), f"{slot['id']} has a rejected custom target: {target_attempts}")

        with urllib.request.urlopen(self.base_url + "/api/proxy/proxies", timeout=15) as response:
            published_ports = {
                int(line.split("@", 1)[1].split(":", 1)[1].split("#", 1)[0])
                for line in response.read().decode("utf-8").splitlines()
                if line.strip()
            }
        self.assertEqual({slot["proxy_port"] for slot in ready}, published_ports)


if __name__ == "__main__":
    unittest.main()
