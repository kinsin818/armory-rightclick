"""Action Router —— 通道核心。

入口无关：SendTo、注册表 verb、IExplorerCommand、Dory 扩展、IN 输入法
最终都只做一件事：把 {action, paths} 递给 route()。

信任模型分两档，这不是形式主义：
    trusted=True   调用方就是用户本人（SendTo 右键传下来的路径），不做路径限制
    trusted=False  调用方是网络（HTTP 总线），必须过鉴权 + 路径白名单

HTTP 总线默认不可用（无 token 拒绝启动、无白名单拒绝所有路径）。
这是审计报告 P0-1 的修复：它曾经是一个「任意本地文件读取 + 侧效应执行」原语。
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import detector
import evidence
import executor

HERE = Path(__file__).resolve().parent
ACTIONS_FILE = HERE / "actions.json"
DEFAULT_PORT = 8791
MAX_BODY = 1 << 20  # 1MB，防止声明巨大 Content-Length 把服务拖死

_STATE_DIR = Path(os.environ.get("LOCALAPPDATA", HERE)) / "Armory"
TOKEN_FILE = _STATE_DIR / "token"

_spec_cache: dict | None = None


def load_actions(force: bool = False) -> dict:
    """动作表缓存。一次进程内不重复读盘。"""
    global _spec_cache
    if _spec_cache is None or force:
        _spec_cache = json.loads(ACTIONS_FILE.read_text(encoding="utf-8"))
    return _spec_cache


def applicable(obj_type: str) -> list[dict]:
    """按对象类型列出可用动作。这是「动态显示动作」的数据来源。"""
    out = []
    for name, meta in load_actions()["actions"].items():
        types = meta.get("types", [])
        if "*" in types or obj_type in types:
            out.append({"name": name, **meta})
    return out


# ---------------------------------------------------------------------------
# Permission Gate
# ---------------------------------------------------------------------------


def _permission_gate(action: str, spec: dict):
    """默认拒绝，不是黑名单。

    任何 risk != none、标注 egress（外发到第三方）、或列入 require_confirm 的动作，
    在确认流程实现之前一律拒绝。新增高危动作默认被拦住，不会悄悄放行。
    """
    policy = spec.get("risk_policy", {})
    meta = spec["actions"].get(action, {})

    if action in policy.get("prototype_deny", []):
        return {"status": "denied",
                "message": f"动作「{action}」在原型阶段拒绝执行（高危清单）"}

    # 不设默认值：risk 键缺失时 meta.get("risk") 得到 None，None != "none" → 拒绝。
    # 曾经写成 meta.get("risk", "none")，于是没声明 risk 的新动作照样放行，
    # 「默认拒绝」只对记得写 risk 字段的动作成立——那不是默认拒绝。
    risk = meta.get("risk")
    if risk != "none":
        return {"status": "denied",
                "message": f"动作「{action}」risk={risk!r}（未声明视为非 none），"
                           f"需确认流程，当前未实现"}

    kind = meta.get("kind")
    if kind not in ("local", "model", "stub"):
        return {"status": "denied",
                "message": f"动作「{action}」kind={kind!r} 未声明或未知，拒绝执行"}

    if action in policy.get("require_confirm", []):
        return {"status": "denied",
                "message": f"动作「{action}」要求确认，当前未实现"}

    return None


def assert_gate_consistency(spec: dict | None = None) -> list[str]:
    """自检：动作表里所有高风险动作必须真的会被拦住。供测试调用。"""
    spec = spec or load_actions()
    problems = []
    for name, meta in spec["actions"].items():
        risky = (meta.get("risk", "none") != "none"
                 or name in spec.get("risk_policy", {}).get("require_confirm", []))
        if risky and _permission_gate(name, spec) is None:
            problems.append(name)
    return problems


# ---------------------------------------------------------------------------
# 路径白名单（仅网络调用方受限）
# ---------------------------------------------------------------------------


def allowed_roots() -> list[Path]:
    raw = os.environ.get("ARMORY_ALLOWED_ROOTS", "").strip()
    if not raw:
        return []
    return [Path(p).resolve() for p in raw.split(";") if p.strip()]


def _path_allowed(target: str, roots: list[Path]) -> bool:
    if not roots:
        return False
    try:
        resolved = Path(target).resolve()
    except OSError:
        return False
    for root in roots:
        try:
            resolved.relative_to(root)
            return True
        except ValueError:
            continue
    return False


# ---------------------------------------------------------------------------
# 主链路
# ---------------------------------------------------------------------------


def route(action: str, paths: list[str], trusted: bool = True) -> dict:
    """完整链路：权限门 → 抽取上下文 → 执行 → 落 evidence。

    trusted=False 时额外校验路径落在白名单内。
    """
    spec = load_actions()
    meta = spec["actions"].get(action)

    if meta is None:
        return {"status": "error", "http": 400, "message": f"动作表内没有「{action}」"}

    # 权限门必须早于上下文抽取：否则被拒绝的动作也留了一份正文快照
    denied = _permission_gate(action, spec)
    if denied:
        denied["http"] = 403
        with evidence.Timer() as t:
            pass
        rec = evidence.write(action, [], denied, t.ms)
        return {"status": "denied", "http": 403, "action": action,
                "objects": [], "result": denied, "evidence": rec}

    if not paths:
        result = {"status": "error", "http": 400, "message": "没有传入任何对象"}
        return {"status": "error", "http": 400, "action": action,
                "objects": [], "result": result}

    if not trusted:
        roots = allowed_roots()
        if not roots:
            result = {"status": "denied", "http": 403,
                      "message": "HTTP 总线未配置 ARMORY_ALLOWED_ROOTS，拒绝处理任何路径"}
            return {"status": "denied", "http": 403, "action": action,
                    "objects": [], "result": result}
        for p in paths:
            if not _path_allowed(p, roots):
                result = {"status": "denied", "http": 403,
                          "message": "路径不在白名单内"}
                return {"status": "denied", "http": 403, "action": action,
                        "objects": [], "result": result}

    with evidence.Timer() as timer:
        objects = [detector.extract(p) for p in paths]

        obj_type = objects[0]["type"]
        if "*" not in meta.get("types", []) and obj_type not in meta.get("types", []):
            result = {"status": "error", "http": 400,
                      "message": f"动作「{action}」不适用「{objects[0]['type_label']}」对象"}
        else:
            result = executor.run(action, objects)

    rec = evidence.write(action, objects, result, timer.ms)
    http = 501 if result.get("status") == "stub" else \
        (400 if result.get("status") == "error" else 200)
    return {"status": result.get("status"), "http": http, "action": action,
            "objects": objects, "result": result, "evidence": rec}


# ---------------------------------------------------------------------------
# HTTP 总线（默认不可用，需 token + 路径白名单）
# ---------------------------------------------------------------------------


def ensure_token() -> str:
    """读取或生成总线 token。只有本机用户能读这个文件。"""
    if TOKEN_FILE.exists():
        return TOKEN_FILE.read_text(encoding="utf-8").strip()
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)
    TOKEN_FILE.write_text(token, encoding="utf-8")
    return token


class _Handler(BaseHTTPRequestHandler):
    server_version = "ArmoryActionRouter"

    def _send(self, code: int, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        # 不宣告任何跨源许可，跨源请求一律失败
        self._send(405, b'{"error":"cross-origin not allowed"}')

    def do_POST(self):
        try:
            self._handle_post()
        except Exception:
            self._send(500, b'{"error":"internal"}')

    def _handle_post(self):
        if urlparse(self.path).path != "/action":
            return self._send(404, b'{"error":"not found"}')

        # 1) Host 必须是本机回环，断掉 DNS rebinding
        host = (self.headers.get("Host") or "").split(":")[0]
        if host not in ("127.0.0.1", "localhost", "::1"):
            return self._send(403, b'{"error":"bad host"}')

        # 2) Origin 一旦出现就必须同源，杜绝网页驱动
        origin = self.headers.get("Origin")
        if origin and not origin.startswith(f"http://{self.headers.get('Host')}"):
            return self._send(403, b'{"error":"bad origin"}')

        # 3) 共享密钥，常量时间比较
        given = self.headers.get("X-Armory-Token", "")
        if not hmac.compare_digest(given, self.server.armory_token):
            return self._send(401, b'{"error":"unauthorized"}')

        # 4) 请求体上限，且 Content-Length 必须是数字
        raw_len = self.headers.get("Content-Length", "")
        try:
            length = int(raw_len)
        except ValueError:
            return self._send(400, b'{"error":"bad content-length"}')
        if length < 0 or length > MAX_BODY:
            return self._send(413, b'{"error":"body too large"}')

        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._send(400, b'{"error":"bad json"}')

        if not isinstance(payload, dict):
            return self._send(400, b'{"error":"bad payload"}')

        out = route(payload.get("action", ""), payload.get("paths", []), trusted=False)
        body = json.dumps(out, ensure_ascii=False).encode("utf-8")
        self._send(out.get("http", 200), body)

    def log_message(self, fmt, *args):
        pass


class _ArmoryHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler, token: str):
        self.armory_token = token
        super().__init__(addr, handler)


def serve(port: int = DEFAULT_PORT, token: str = ""):
    if not token:
        token = ensure_token()
    if not allowed_roots():
        raise SystemExit(
            "拒绝启动：未配置 ARMORY_ALLOWED_ROOTS。\n"
            "HTTP 总线会把本地文件读取能力暴露给本机任意进程，必须先限定可访问的根目录，例如：\n"
            "  set ARMORY_ALLOWED_ROOTS=D:\\Armory\n"
        )
    httpd = _ArmoryHTTPServer(("127.0.0.1", port), _Handler, token)
    print(f"Armory Action Router 监听 127.0.0.1:{port}")
    print(f"  token 文件: {TOKEN_FILE}")
    print(f"  允许的根目录: {', '.join(str(r) for r in allowed_roots())}")
    print("  请求需带 X-Armory-Token 头，Host 必须是 127.0.0.1/localhost")
    httpd.serve_forever()


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    serve(port)
