"""对象类型检测与上下文抽取。

Context Extractor 的前半段：判定「用户右键的到底是什么」。
只做判定与抽取，不做任何动作、不写任何文件。

预览（preview）默认关闭。原因：正文会被写进 evidence，而 evidence 曾经
随仓库进 git，等于把用户文件内容存进版本历史（审计报告 P0-2）。
需要预览时用环境变量 ARMORY_CAPTURE_PREVIEW=1 打开，且敏感文件一律不抽。
"""
from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime
from pathlib import Path

CODE_EXT = {
    ".py", ".pyw", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".java", ".kt", ".kts", ".go", ".rs", ".c", ".h", ".cpp", ".hpp", ".cc",
    ".cs", ".rb", ".php", ".swift", ".scala", ".lua", ".sh", ".bash", ".zsh",
    ".ps1", ".psm1", ".bat", ".cmd", ".sql", ".r", ".m", ".vim",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".xml",
    ".html", ".htm", ".css", ".scss", ".less", ".vue", ".svelte",
}

IMAGE_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tiff", ".tif",
    ".ico", ".svg", ".heic", ".heif", ".avif", ".raw", ".cr2", ".psd",
}

DOC_EXT = {
    ".md", ".markdown", ".txt", ".pdf", ".docx", ".doc", ".xlsx", ".xls",
    ".pptx", ".ppt", ".csv", ".tsv", ".rtf", ".epub", ".odt", ".log",
}

ARCHIVE_EXT = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".zst",
    ".iso", ".cab", ".msi", ".apk", ".jar", ".whl",
}

TYPE_LABEL = {
    "folder": "文件夹",
    "code": "代码",
    "image": "图片",
    "document": "文档",
    "archive": "压缩包",
    "text": "文本",
    "binary": "二进制",
    "missing": "路径不存在",
}

# 这些文件一律不抽正文，哪怕开了预览开关
_SENSITIVE_NAME_RE = re.compile(
    r"(^|\\)(\.env|.*secret.*|.*creden.*|.*key.*|.*token.*|.*config.*\.json$"
    r"|.*\.pem$|.*\.p12$|.*\.pfx$|.*\.pfx|id_rsa.*)",
    re.IGNORECASE,
)

# 正文里的凭据形状，抽预览时一律抹掉
_SECRET_RE = re.compile(
    r"(nvapi-[A-Za-z0-9_\-]+"
    r"|sk-[A-Za-z0-9_\-]{8,}"
    r"|-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----"
    r"|(?:api[_-]?key|token|password|passwd|secret)\s*[:=]\s*\S+)",
    re.IGNORECASE,
)

PREVIEW_MAX_CHARS = 200


def capture_preview_enabled() -> bool:
    return os.environ.get("ARMORY_CAPTURE_PREVIEW", "").strip() in ("1", "true", "yes")


def detect(target: str) -> str:
    """判定对象类型。返回值见 TYPE_LABEL。"""
    path = Path(target)
    if not path.exists():
        return "missing"
    if path.is_dir():
        return "folder"

    ext = path.suffix.lower()
    if ext in CODE_EXT:
        return "code"
    if ext in IMAGE_EXT:
        return "image"
    if ext in ARCHIVE_EXT:
        return "archive"
    if ext in DOC_EXT:
        return "document"
    if _looks_text(path):
        return "text"
    return "binary"


def _looks_text(path: Path, sample: int = 4096) -> bool:
    """无扩展名时的兜底判定：采样里有没有 NUL 字节。"""
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(sample)
    except OSError:
        return False
    if not chunk:
        return True
    return b"\x00" not in chunk


def looks_text_path(target: str) -> bool:
    """对外暴露给执行层：送模型之前先确认这不是二进制。"""
    return _looks_text(Path(target))


def sha256(target: str, chunk_size: int = 1 << 20) -> str:
    """算文件 SHA-256。目录返回空串（目录没有单一哈希）。"""
    path = Path(target)
    if not path.is_file():
        return ""
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            while True:
                block = fh.read(chunk_size)
                if not block:
                    break
                digest.update(block)
    except OSError:
        return ""
    return digest.hexdigest()


def _walk_stats(path: Path, max_files: int = 5000):
    """遍历目录统计。超过 max_files 就停，避免大目录卡死右键。"""
    file_count = 0
    total_size = 0
    truncated = False
    ext_counter: dict[str, int] = {}

    for root, _dirs, names in os.walk(path):
        for name in names:
            if file_count >= max_files:
                truncated = True
                break
            file_count += 1
            try:
                total_size += (Path(root) / name).stat().st_size
            except OSError:
                pass
            ext = Path(name).suffix.lower() or "(无扩展名)"
            ext_counter[ext] = ext_counter.get(ext, 0) + 1
        if truncated:
            break

    return file_count, total_size, truncated, ext_counter


def _redact(text: str) -> str:
    return _SECRET_RE.sub("[REDACTED]", text)


def is_sensitive_path(target: str) -> bool:
    """路径是否落在敏感名单里（key / secret / token / .env / config.json / .pem …）。

    本地留存和外发两条路都要问这个函数。第 2 轮审计的 P0 就是：返修只在
    本地留存那条路上接了它，外发那条一条没接，导致右键「总结」自己的
    model_config.json 会把明文 key 发给第三方模型。
    """
    p = Path(target)
    return bool(_SENSITIVE_NAME_RE.search(str(p)) or _SENSITIVE_NAME_RE.search(p.name))


def redact(text: str) -> tuple[str, int]:
    """抹掉文本里的凭据形状，返回 (脱敏后文本, 抹掉处数)。"""
    return _SECRET_RE.subn("[REDACTED]", text)


def _read_preview(path: Path, max_lines: int = 30, max_bytes: int = 8192):
    """读前若干行做预览。默认不开；开了也要脱敏并压到 200 字符。"""
    if not capture_preview_enabled():
        return None
    if is_sensitive_path(str(path)):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read(max_bytes)
    except OSError:
        return None

    lines = raw.splitlines()
    head = "\n".join(lines[:max_lines])
    head = _redact(head)
    if len(head) > PREVIEW_MAX_CHARS:
        head = head[:PREVIEW_MAX_CHARS] + "…（预览已截断）"
    return len(lines), head


def extract(target: str) -> dict:
    """抽取对象上下文。返回纯 dict，可直接 json 序列化。

    一次 lstat 复用，避免同一路径反复 stat 造成的 TOCTOU 与冗余系统调用。
    """
    path = Path(target)
    stat = None
    try:
        stat = os.lstat(str(path)) if os.path.lexists(str(path)) else None
    except OSError:
        stat = None

    exists = stat is not None
    obj_type = detect(target) if exists else "missing"

    ctx: dict = {
        "path": str(path.resolve()) if exists else str(path),
        "name": path.name or str(path),
        "type": obj_type,
        "type_label": TYPE_LABEL.get(obj_type, obj_type),
        "exists": exists,
    }

    if not exists:
        return ctx

    is_dir = os.path.isdir(str(path))
    if is_dir:
        count, size, truncated, exts = _walk_stats(path)
        ctx.update({
            "size_bytes": size,
            "file_count": count,
            "truncated": truncated,
            "top_extensions": sorted(exts.items(), key=lambda kv: -kv[1])[:8],
        })
        return ctx

    ctx.update({
        "size_bytes": stat.st_size,
        "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        "extension": path.suffix.lower(),
    })

    if obj_type in ("code", "text", "document"):
        head = _read_preview(path)
        if head is not None:
            ctx["line_count"] = head[0]
            ctx["char_count"] = stat.st_size
            ctx["preview"] = head[1]

    return ctx
