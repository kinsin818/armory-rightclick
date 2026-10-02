"""发布前敏感内容复扫。

push 之前跑一遍：

    python scripts/pre_publish_scan.py

扫描 git 已跟踪的所有文件（外加可选的 LICENSE），命中任何一条就直接非零退出。
检查五类东西：内部盘符路径、家目录、真实凭据形状、凭据文件名、内部提交 hash。

这不是形式主义。本仓库曾差点把「密钥文件存放在哪、有几条」写进 README 公开出去，
代码层当时是干净的，漏的全在文档里。

两条自我约束：
  1. 凭据类命中**只打掩码**。命中原文打进 stdout，等于把真 key 写进终端回滚缓冲
     ——贴给助手、截图、录屏都会带走一次（第 4 轮 M-11）。
  2. 整改指引要说对场景。无 `.git` 的解包目录里「git rm --cached」是句废话，
     正确动作是「把文件从包里删掉」（第 4 轮 M-13）。
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
}

# 这几类命中绝不能回显原文——打印一次就等于泄露一次。
# 路径、hash 之类回显是安全的（它们本来就要靠原文定位），凭据不是。
MASKED_KINDS = {"真实凭据形状"}

# 提交 hash：整行判定——一行里同时有「长 hex」和「版本控制关键词」才算命中。
# 曾经写成前瞻 `(?=.*(?:提交|commit|HEAD))`，只覆盖 hash 在关键词之前，而中文
# 语序里「上一轮的提交号 6203c0d5」恰恰是关键词在前，漏的正是常态那一种（M-12）。
_HASH_HEX_RE = re.compile(r"\b[0-9a-f]{7,40}\b")
_HASH_CTX_RE = re.compile(r"提交|commit|HEAD|cherry-?pick|revert|\bhash\b")

# 允许出现的地方：这些是判据本身或测试假数据，不是真的泄露
ALLOWED = {
    "detector.py",                  # 脱敏正则本身
    "tests/test_channel.py",        # 测试用例里的假 key
    "scripts/pre_publish_scan.py",  # 本脚本自己的模式表
}


def _allowed(rel: str) -> bool:
    name = rel.replace("\\", "/")
    return name in ALLOWED or name.split("/")[-1] in ALLOWED


SCAN_EXTS = {".py", ".md", ".json", ".ps1", ".yml", ".yaml", ".txt", ""}


def tracked_files() -> tuple[list[str], bool]:
    """返回 (文件列表, 是否来自 git)。

    优先用 git ls-files；不在 git 仓库里（导出快照、解压的压缩包）就扫目录。
    只依赖 git 的话，脚本在「检查即将发布的 zip」这种场景下会几乎扫不到东西。
    """
    out = subprocess.run(["git", "ls-files"], cwd=ROOT,
                         capture_output=True, text=True)
    files = [f for f in out.stdout.splitlines() if f.strip()]
    if files:
        return files, True

    return [
        str(p.relative_to(ROOT))
        for p in ROOT.rglob("*")
        if p.is_file() and p.suffix.lower() in SCAN_EXTS and ".git" not in p.parts
    ], False


def _mask(text: str) -> str:
    """只留头尾各几个字符：够定位，不够复制走。"""
    s = text[:60]
    if len(s) <= 8:
        return (s[:2] + "…" + s[-1:]) if s else ""
    return f"{s[:4]}…{s[-2:]}"


def main() -> int:
    files, from_git = tracked_files()
    extra = [p for p in ("LICENSE", "README.md") if (ROOT / p).exists()]
    targets = sorted(set(files) | set(extra))

    hits: list[str] = []

    # 配置文件本身绝不能进发布包：它含 API key，push 上去等于密钥公开。
    # 指引按场景分述——无 git 时（解包目录 / zip 内容）没有「取消跟踪」这回事。
    if any("model_config.json" in f for f in files):
        if from_git:
            hits.append("model_config.json 已被 git 跟踪 —— 含 API key，"
                        "立刻 git rm --cached model_config.json 并确认 .gitignore 覆盖它")
        else:
            hits.append("发布包里含 model_config.json（非 git 目录，无法 git rm）——"
                        "含 API key，把它从包里删掉再发布")

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
                shown = _mask(m.group()) if name in MASKED_KINDS else m.group()[:60]
                hits.append(f"{rel}:{line}  [{name}] {shown!r}")

        for i, line in enumerate(text.splitlines(), 1):
            m = _HASH_HEX_RE.search(line)
            if m and _HASH_CTX_RE.search(line):
                hits.append(f"{rel}:{i}  [内部提交 hash] {m.group()!r}")

    if hits:
        print("发布前复扫：命中敏感内容，禁止 push")
        for h in hits:
            print("  " + h)
        return 1

    print(f"发布前复扫：干净（扫描 {len(targets)} 个文件，"
          f"{len(PATTERNS) + 1} 类模式，{'git' if from_git else '目录扫描'}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
