import unittest
from pathlib import Path


class DashboardContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = Path("index.html").read_text(encoding="utf-8")

    def test_multi_exit_view_has_required_api_and_actions(self):
        for marker in (
            'id="multi-exit-grid"',
            "/api/local/exits",
            "/api/local/nodes",
            "pcSaveExitSlot",
            "pcRedialExitSlot",
            "pcEnableExitSlot",
            "pcDisableExitSlot",
            "pcLoadCandidateNodes",
            "pcConnectCandidateNode",
            "选择候选节点",
        ):
            self.assertIn(marker, self.html)

    def test_multi_exit_cards_show_runtime_and_original_checks(self):
        for marker in (
            "proxy_port",
            "egress_ip",
            "failure_streak",
            "check_result",
            "last_error",
            "current_node",
        ):
            self.assertIn(marker, self.html)

    def test_dashboard_does_not_claim_accepted_redial_is_connected(self):
        self.assertIn("重拨请求已接受，等待槽位重新就绪", self.html)
        self.assertNotIn("重拨成功，出口已连接", self.html)

    def test_local_proxy_table_uses_actual_channel_count(self):
        self.assertIn("${details.length} 个通道", self.html)
        self.assertNotIn("${details.length} / 2", self.html)

    def test_management_actions_are_local_not_empty_managed_vps_fanout(self):
        self.assertIn("pcSavePrimaryExitSlot", self.html)
        self.assertIn("pcRedialPrimaryExitSlot", self.html)
        self.assertNotIn("if (!targets.length) throw new Error('暂无已接入 VPS');", self.html)

    def test_local_dashboard_has_no_management_login_flow(self):
        for removed in (
            "系统准入",
            "登入系统",
            "showLoginModal",
            "@click=\"logout\"",
            "const logout =",
            "const login =",
            "isLoggedIn",
            "authKey",
            "authGeneration",
            "currentUser",
            "Authorization",
            "Bearer",
            "agent_token",
            "/api/agent_update",
            "请先刷新页面以签发独立 Agent Token",
            "apk update",
            "Agent 下次心跳",
            "实时下发",
            "功能规划占位",
        ):
            self.assertNotIn(removed, self.html)

    def test_realm_and_local_deployment_views_call_real_local_apis(self):
        for marker in (
            "/api/realm",
            "loadRealmStatus",
            "saveRealmConfig",
            "startRealm",
            "stopRealm",
            "restartRealm",
            "/api/local/deploy-command",
            "loadDeployCommand",
            "docker compose up -d --build",
        ):
            self.assertIn(marker, self.html)
        self.assertNotIn("本地多出口模式不启动独立 Realm 进程", self.html)

    def test_multi_exit_cards_explain_real_publishability_and_probe_attempts(self):
        for marker in (
            "listener_ready",
            "targets.attempts",
            "attempt.url",
            "attempt.code",
            "attempt.classification",
            "attempt.error",
            "目标明确应答 403",
            "未发布到订阅",
        ):
            self.assertIn(marker, self.html)
        self.assertNotIn("403（可正常使用）", self.html)

    def test_management_requests_do_not_send_cloud_session_headers(self):
        self.assertNotIn("kuiAdminAuthHeader", self.html)
        self.assertNotIn("getPcAuthHeader", self.html)
        self.assertNotIn("realtimeUrl", self.html)
        self.assertNotIn("switchProxyIP", self.html)

    def test_local_dashboard_preserves_all_original_admin_sections(self):
        for marker in (
            "服务器与节点",
            "多用户管理",
            "住宅IP代理",
            "Realm中转",
            "第三方服务",
            "第三方订阅",
            "系统设置",
            "探针全景大盘",
            "节点出口",
            "选择候选节点",
        ):
            self.assertIn(marker, self.html)

    def test_local_dashboard_does_not_present_placeholder_or_cloud_only_copy(self):
        for removed in (
            "未来规划，敬请期待",
            "读取 Pages 环境变量",
            "主备双活调度引擎",
            "tun_main / tun_backup",
            "VPS 实时运行日志",
            "住宅双隧道",
            "双路通道失联",
            "STANDBY (热备就绪)",
        ):
            self.assertNotIn(removed, self.html)
        for marker in (
            "d.isp.flag === 'residential'",
            "d.isp.flag === 'hosting'",
            "ISP/未知",
        ):
            self.assertIn(marker, self.html)

        self.assertNotIn("const tags = isHosting\n", self.html)
        self.assertIn("本地模式状态", self.html)
        self.assertIn("每个槽位独立运行一条 OpenVPN 隧道", self.html)


if __name__ == "__main__":
    unittest.main()
