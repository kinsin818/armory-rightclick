"""Evidence Writer。

每次动作执行落一条记录，带 SHA-256，供后续审计闭环。

默认落盘位置在仓库之外（%LOCALAPPDATA%\\Armory\\evidence）。原因：证据体里
可能带对象上下文，随仓库进 git 会造成内容外泄。这个默认值就是审计报告
P0-2 的修复。
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime
from pathlib import Path


def default_dir() -> Path:
    """一律落在仓库之外。可用 ARMORY_EVIDENCE_DIR 覆盖。

    曾经在 LOCALAPPDATA 缺失时回落到 <仓库>/evidence，而 .gitignore 又没写
    evidence/ ，等于给 P0-2 留了一条原路复活的通道。现在回落到用户目录。
    """
    override = os.environ.get("ARMORY_EVIDENCE_DIR", "").strip()
    if override:
        return Path(override)
    local = os.environ.get("LOCALAPPDATA", "").strip()
    if local:
        return Path(local) / "Armory" / "evidence"
    return Path.home() / ".armory" / "evidence"


def _canonical(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def fingerprint(payload: dict) -> str:
    """对整个证据体做 SHA-256。"""
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def write(action: str, objects: list[dict], result: dict,
          elapsed_ms: int = 0) -> dict:
    """落一条证据，返回证据体本身（含 sha256 与文件路径）。

    elapsed_ms 让性能断言变成有留痕的可复证事实，而不是 README 里的一句自述。
    """
    out_dir = default_dir()
    out_dir.mkdir(parents=True, exist_ok=True)

    # 时间戳只取一次：否则跨秒时文件名与体内时间戳不一致，sha256 与文件名对不上
    now = datetime.now()
    stamp = now.strftime("%Y%m%d-%H%M%S")

    body = {
        "timestamp": now.isoformat(timespec="seconds"),
        "elapsed_ms": elapsed_ms,
        "action": action,
        "objects": objects,
        "result": result,
    }
    body["sha256"] = fingerprint(body)

    path = out_dir / f"{stamp}-{action}.json"
    counter = 1
    while path.exists():
        path = out_dir / f"{stamp}-{action}-{counter}.json"
        counter += 1

    path.write_text(json.dumps(body, ensure_ascii=False, indent=2), encoding="utf-8")
    body["evidence_path"] = str(path)
    return body


class Timer:
    """with Timer() as t: ... ; t.ms 即为耗时。"""

    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *exc):
        self.ms = int((time.perf_counter() - self._start) * 1000)
        return False

    ms = 0
