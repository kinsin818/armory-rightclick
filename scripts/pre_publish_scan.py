"""发布前敏感内容复扫。

push 之前跑一遍：

    python scripts/pre_publish_scan.py

扫描 git 已跟踪的所有文件（外加可选的 LICENSE），命中任何一条就直接非零退出。
检查五类东西：内部盘符路径、家目录、真实凭据形状、凭据文件名、内部提交 hash。

这不是形式主义。本仓库曾差点把「密钥文件存放在哪、有几条」写进 README 公开出去，
代码层当时是干净的，漏的全在文档里。
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PATTERNS = {
    "内部盘符路径": r"[A-Za-z]:\\(codex|marvis|新建文件夹|Armory[\\])",
    "家目录": r"C:\\Users\\|/home/[A-Za-z0-9_]+/|/Users/[A-Za-z0-9_]+/",
    "真实凭据形状": (
        r"nvapi-[A-Za-z0-9]{16,}"
        r"|sk-[A-Za-z0-9]{16,}"
        r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    ),
    "凭据文件名": r"\b(key|secret|token|credential)s?\.txt\b",
    "内部提交 hash": r"\b[0-9a-f]{7,40}\b(?=.*(?:提交|commit|HEAD))",
}

# 允许出现的地方：这些是判据本身或测试假数据，不是真的泄露
ALLOWED = {
    "detector.py",                  # 脱敏正则本身
    "tests/test_channel.py",        # 测试用例里的假 key
    "scripts/pre_publish_scan.py",  # 本脚本自己的模式表
}


def _allowed(rel: str) -> bool:
    name = rel.replace("\\", "/")
    return name in ALLOWED or name.split("/")[-1] in ALLOWED


def tracked_files() -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT,
                         capture_output=True, text=True)
    return [f for f in out.stdout.splitlines() if f.strip()]


def main() -> int:
    files = tracked_files()
    extra = [p for p in ("LICENSE", "README.md") if (ROOT / p).exists()]
    targets = sorted(set(files) | set(extra))

    hits: list[str] = []

    # 配置文件本身绝不能被跟踪：它含 API key，push 上去等于密钥公开
    if any("model_config.json" in f for f in files):
        hits.append("model_config.json 已被 git 跟踪 —— 含 API key，"
                    "立刻 git rm --cached model_config.json")
    for rel in targets:
        path = ROOT / rel
        if not path.exists() or _allowed(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for name, pattern in PATTERNS.items():
            for m in re.finditer(pattern, text):
                line = text[: m.start()].count("\n") + 1
                hits.append(f"{rel}:{line}  [{name}] {m.group()[:60]!r}")

    if hits:
        print("发布前复扫：命中敏感内容，禁止 push")
        for h in hits:
            print("  " + h)
        return 1

    print(f"发布前复扫：干净（扫描 {len(targets)} 个文件，{len(PATTERNS)} 类模式）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
