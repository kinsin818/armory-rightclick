"""Evidence Writer。

每次动作执行落一条记录，带 SHA-256，供后续审计闭环。
写入即完成，不做任何推断。
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

EVIDENCE_DIR = Path(__file__).resolve().parent / "evidence"


def _canonical(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def fingerprint(payload: dict) -> str:
    """对整个证据体做 SHA-256。"""
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def write(action: str, objects: list[dict], result: dict) -> dict:
    """落一条证据，返回证据体本身（含 sha256 与文件路径）。"""
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    body = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "action": action,
        "objects": objects,
        "result": result,
    }
    body["sha256"] = fingerprint(body)

    path = EVIDENCE_DIR / f"{stamp}-{action}.json"
    counter = 1
    while path.exists():
        path = EVIDENCE_DIR / f"{stamp}-{action}-{counter}.json"
        counter += 1

    path.write_text(
        json.dumps(body, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    body["evidence_path"] = str(path)
    return body
