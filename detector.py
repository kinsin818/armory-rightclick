"""对象类型检测与上下文抽取。

Context Extractor 的前半段：判定「用户右键的到底是什么」。
只做判定与抽取，不做任何动作、不写任何文件。
"""
from __future__ import annotations

import hashlib
import os
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


def extract(target: str) -> dict:
    """抽取对象上下文。返回纯 dict，可直接 json 序列化。"""
    path = Path(target)
    obj_type = detect(target)

    ctx: dict = {
        "path": str(path.resolve()) if path.exists() else str(path),
        "name": path.name or str(path),
        "type": obj_type,
        "type_label": TYPE_LABEL.get(obj_type, obj_type),
        "exists": path.exists(),
    }

    if not path.exists():
        return ctx

    if path.is_dir():
        count, size, truncated, exts = _walk_stats(path)
        ctx.update({
            "size_bytes": size,
            "file_count": count,
            "truncated": truncated,
            "top_extensions": sorted(exts.items(), key=lambda kv: -kv[1])[:8],
        })
        return ctx

    try:
        stat = path.stat()
    except OSError:
        return ctx

    ctx.update({
        "size_bytes": stat.st_size,
        "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        "extension": path.suffix.lower(),
    })

    if obj_type in ("code", "text", "document"):
        head = _read_head(path)
        if head is not None:
            ctx["line_count"] = head[0]
            ctx["char_count"] = stat.st_size
            ctx["preview"] = head[1]

    return ctx


def _read_head(path: Path, max_lines: int = 30, max_bytes: int = 8192):
    """读前若干行做预览。二进制或读取失败返回 None。"""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read(max_bytes)
    except OSError:
        return None

    lines = raw.splitlines()
    return len(lines), "\n".join(lines[:max_lines])
