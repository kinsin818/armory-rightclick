"""Action Router —— 通道核心。

入口无关：SendTo、注册表 verb、IExplorerCommand、Dory 扩展、IN 输入法
最终都只做一件事：把 {action, paths} 递给 route()。
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

import detector
import evidence
import executor

HERE = Path(__file__).resolve().parent
ACTIONS_FILE = HERE / "actions.json"
DEFAULT_PORT = 8791


def load_actions() -> dict:
    return json.loads(ACTIONS_FILE.read_text(encoding="utf-8"))


def applicable(obj_type: str) -> list[dict]:
    """按对象类型列出可用动作。这是「动态显示动作」的数据来源。"""
    spec = load_actions()
    out = []
    for name, meta in spec["actions"].items():
        types = meta.get("types", [])
        if "*" in types or obj_type in types:
            out.append({"name": name, **meta})
    return out


def _permission_gate(action: str, spec: dict):
    """Permission Gate。原型阶段对高危动作一律拒绝，不做半成品。"""
    policy = spec.get("risk_policy", {})
    if action in policy.get("prototype_deny", []):
        return {
            "status": "denied",
            "message": f"动作「{action}」属高危动作，原型阶段拒绝执行（需确认流程未实现）",
        }
    return None


def route(action: str, paths: list[str]) -> dict:
    """完整链路：抽取上下文 → 权限门 → 执行 → 落 evidence。"""
    spec = load_actions()
    meta = spec["actions"].get(action)

    if meta is None:
        return {"status": "error", "message": f"动作表内没有「{action}」"}

    objects = [detector.extract(p) for p in paths]

    denied = _permission_gate(action, spec)
    if denied:
        result = denied
    else:
        obj_type = objects[0]["type"]
        if "*" not in meta.get("types", []) and obj_type not in meta.get("types", []):
            result = {
                "status": "error",
                "message": f"动作「{action}」不适用「{objects[0]['type_label']}」对象",
            }
        else:
            result = executor.run(action, objects)

    rec = evidence.write(action, objects, result)
    return {"status": result.get("status"), "action": action, "objects": objects,
            "result": result, "evidence": rec}


# ---------------------------------------------------------------------------
# 可选常驻服务：供未来其他入口（Dory / IN / IExplorerCommand 壳）接入
# ---------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if urlparse(self.path).path != "/action":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self.send_error(400, "bad json")
            return

        out = route(payload.get("action", ""), payload.get("paths", []))
        body = json.dumps(out, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def serve(port: int = DEFAULT_PORT):
    HTTPServer(("127.0.0.1", port), _Handler).serve_forever()


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    print(f"Armory Action Router 监听 127.0.0.1:{port}  POST /action  {{\"action\":..., \"paths\":[...]}}")
    serve(port)
