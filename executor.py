"""动作执行层。

三类：
  local —— 本机真实执行，不联网
  model —— 调模型（需 model_config.json 或 ARMORY_LLM_* 环境变量）
  stub  —— 尚未接线，明确返回未接线，绝不假装成功
"""
from __future__ import annotations

import re
import struct
import subprocess
import tempfile
from pathlib import Path

import detector
import model

HERE = Path(__file__).resolve().parent
OCR_PS1 = HERE / "ocr.ps1"

# ---------------------------------------------------------------------------
# local handlers
# ---------------------------------------------------------------------------


def _h_info(ctx: dict) -> dict:
    return {"status": "ok", "kind": "local", "data": ctx}


def _h_hash(ctx: dict) -> dict:
    digest = detector.sha256(ctx["path"])
    if not digest:
        return {"status": "error", "kind": "local", "message": "无法读取（目录或读取失败）"}
    return {"status": "ok", "kind": "local", "clipboard": digest, "data": {"sha256": digest}}


def _h_paths(objects: list[dict]) -> dict:
    text = "\n".join(o["path"] for o in objects)
    return {"status": "ok", "kind": "local", "clipboard": text, "data": {"count": len(objects)}}


_DEF_RE = re.compile(
    r"^\s*(?:export\s+)?(?:async\s+)?"
    r"(?:def|class|function|func|fn|struct|interface|enum|trait|impl|const|let|var)\s+"
    r"([A-Za-z_]\w*)",
    re.MULTILINE,
)
_IMPORT_RE = re.compile(
    r"^\s*(?:import|from|using|require|include|package)\s+[\w.\\/\-'\"]+",
    re.MULTILINE,
)


def _h_outline(ctx: dict) -> dict:
    path = Path(ctx["path"])
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"status": "error", "kind": "local", "message": f"读取失败：{exc}"}

    imports = [m.group(0).strip()[:100] for m in _IMPORT_RE.finditer(text)]
    defs = [m.group(1) for m in _DEF_RE.finditer(text)]

    lines = [
        f"# 结构：{path.name}", "",
        f"- 总行数：{len(text.splitlines())}",
        f"- 顶层定义数：{len(defs)}",
        f"- import/引用数：{len(imports)}", "",
        "## 顶层定义",
    ]
    lines += [f"- `{d}`" for d in defs[:80]] or ["- （无）"]
    if len(defs) > 80:
        lines.append(f"- …… 另有 {len(defs) - 80} 个")
    lines += ["", "## import / 引用"]
    lines += [f"- `{i}`" for i in imports[:40]] or ["- （无）"]

    return {"status": "ok", "kind": "local", "clipboard": "\n".join(lines),
            "data": {"defs": len(defs)}}


def _png_size(data: bytes):
    if len(data) >= 24 and data[:8] == b"\x89PNG\r\n\x1a\n":
        return struct.unpack(">II", data[16:24])
    return None


def _gif_size(data: bytes):
    if len(data) >= 10 and data[:3] == b"GIF":
        return struct.unpack("<HH", data[6:10])
    return None


def _jpeg_size(data: bytes):
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        return None
    i = 2
    while i < len(data) - 9:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
                      0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            h, w = struct.unpack(">HH", data[i + 5:i + 9])
            return w, h
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        i += 2 + struct.unpack(">H", data[i + 2:i + 4])[0]
    return None


def _h_imgmeta(ctx: dict) -> dict:
    path = Path(ctx["path"])
    try:
        with open(path, "rb") as fh:
            head = fh.read(65536)
    except OSError as exc:
        return {"status": "error", "kind": "local", "message": f"读取失败：{exc}"}

    size = _png_size(head) or _gif_size(head) or _jpeg_size(head)
    info = {
        "format": path.suffix.lower().lstrip(".") or "未知",
        "size_bytes": ctx.get("size_bytes"),
        "pixels": f"{size[0]}x{size[1]}" if size else "本原型未解析（仅支持 PNG/GIF/JPEG）",
    }
    text = f"{path.name} · {info['format']} · {info['pixels']} · {info['size_bytes']} 字节"
    return {"status": "ok", "kind": "local", "clipboard": text, "data": info}


def _h_index(ctx: dict) -> dict:
    path = Path(ctx["path"])
    exts = ctx.get("top_extensions", [])
    mb = (ctx.get("size_bytes") or 0) / 1048576

    lines = [
        f"# 目录索引：{path.name}", "",
        f"- 路径：`{path}`",
        f"- 文件数：{ctx.get('file_count')}" + ("（已截断统计）" if ctx.get("truncated") else ""),
        f"- 总体积：{mb:.2f} MB", "",
        "## 扩展名分布",
    ]
    lines += [f"- `{ext}` × {n}" for ext, n in exts] or ["- （空目录）"]
    return {"status": "ok", "kind": "local", "clipboard": "\n".join(lines),
            "data": {"file_count": ctx.get("file_count")}}


# ---------------------------------------------------------------------------
# OCR：Windows 自带引擎，本地跑，不联网不花钱
# ---------------------------------------------------------------------------


def _h_ocr(ctx: dict) -> dict:
    if not OCR_PS1.exists():
        return {"status": "error", "kind": "local", "message": f"缺少 {OCR_PS1}"}

    with tempfile.TemporaryDirectory() as tmp:
        out_file = Path(tmp) / "ocr.txt"
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-File", str(OCR_PS1), "-Path", ctx["path"], "-OutFile", str(out_file)],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
        )
        text = out_file.read_text(encoding="utf-8") if out_file.exists() else ""

    if text.startswith("__OCR_NO_ENGINE__"):
        return {
            "status": "error", "kind": "local",
            "message": "系统没有可用的 OCR 引擎。需在「设置 → 语言」里安装中文（简体）OCR 语言包。",
        }
    if text.startswith("__OCR_ERROR__"):
        return {"status": "error", "kind": "local", "message": text}

    text = text.strip()
    if not text:
        return {"status": "ok", "kind": "local", "clipboard": "（图中未识别到文字）", "data": {"lines": 0}}

    header = f"# OCR：{ctx['name']}\n\n"
    return {"status": "ok", "kind": "local", "clipboard": header + text,
            "data": {"chars": len(text), "lines": len(text.splitlines())}}


# ---------------------------------------------------------------------------
# model handlers
# ---------------------------------------------------------------------------

_SUMMARY_SYS = (
    "你是 Armory 右键增强的总结引擎。用户右键点击了一个文件并选择了「总结」。\n"
    "要求：用简体中文输出；分点；不超过 6 条；只说关键信息，不要复述原文；直接给结果。"
)

_TRANSLATE_SYS = (
    "你是翻译引擎。要求：只输出译文，不要解释、不要加前后缀、不要保留原文。\n"
    "译文语言由输入决定：中文输入译英文，非中文输入译简体中文。术语和代码标识符保持原样。"
)

_DESCRIBE_SYS = "You are a vision assistant."


def _read_for_model(ctx: dict, limit: int = 0) -> str:
    if not limit:
        limit = int(model.load_config().get("max_input_chars", 6000))
    try:
        raw = Path(ctx["path"]).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise RuntimeError(f"读取失败：{exc}")
    if not raw.strip():
        raise RuntimeError("文件内容为空，没什么可处理的")
    return model.clip(raw, limit)


def _h_summarize(ctx: dict) -> dict:
    text = _read_for_model(ctx)
    out = model.chat(_SUMMARY_SYS, f"文件：{ctx['name']}\n\n{text}", max_tokens=2000)
    body = f"# 总结：{ctx['name']}\n\n{out}"
    return {"status": "ok", "kind": "model", "clipboard": body,
            "data": {"model": model.load_config().get("model")}}


def _h_translate(ctx: dict) -> dict:
    # 翻译送全文既慢又烧额度，且长输入会诱出推理模型的思考过程，单独压到 3000 字符
    text = _read_for_model(ctx, limit=3000)
    out = model.chat(_TRANSLATE_SYS, text, max_tokens=3000)
    return {"status": "ok", "kind": "model", "clipboard": out,
            "data": {"model": model.load_config().get("model")}}


def _h_describe(ctx: dict) -> dict:
    """两步：视觉模型出描述（中文能力弱，常给英文）→ 文本模型译中文。

    为什么不直接用大视觉模型出中文：实测 90b 视觉要走 60 秒以上，右键等不起。
    11b 视觉约 7 秒，加一步 3 秒翻译，总共 10 秒出中文，划算。
    """
    raw = model.vision(
        ctx["path"],
        "Describe this image: what is the subject, what text or UI elements are visible, "
        "and what it might be used for. Be factual, no more than 6 sentences. "
        "Do not invent details you cannot see.",
        max_tokens=600,
    )

    cn = raw
    if _looks_mostly_non_chinese(raw):
        try:
            cn = model.chat(
                "你是翻译引擎。把下面的图片描述翻译成简体中文，只输出译文，不要解释。",
                raw, max_tokens=800,
            )
        except RuntimeError:
            cn = raw  # 翻译失败就退回原文，不装作成功也不丢结果

    body = f"# 图片描述：{ctx['name']}\n\n{cn}"
    return {"status": "ok", "kind": "model", "clipboard": body,
            "data": {"vision_model": model.load_config().get("vision_model"),
                     "translated": cn is not raw}}


def _looks_mostly_non_chinese(text: str) -> bool:
    """粗判：汉字占比低于 15% 就认为需要翻译。"""
    if not text:
        return False
    han = sum(1 for ch in text if "\u4e00" <= ch <= "\u9fff")
    return han / max(len(text), 1) < 0.15


# ---------------------------------------------------------------------------
# 分发
# ---------------------------------------------------------------------------

_SINGLE = {
    "info": _h_info,
    "hash": _h_hash,
    "outline": _h_outline,
    "imgmeta": _h_imgmeta,
    "index": _h_index,
    "ocr": _h_ocr,
    "summarize": _h_summarize,
    "translate": _h_translate,
    "describe": _h_describe,
}

_STUB_NEEDS = {
    "audit": "GOLink 调度通道",
    "rename": "模型接入 + 高危动作确认流程",
}


def run(action: str, objects: list[dict]) -> dict:
    """执行动作。objects 是 detector.extract 的结果列表。"""
    if not objects:
        return {"status": "error", "message": "没有传入任何对象"}

    if action == "paths":
        return _h_paths(objects)

    if action in _STUB_NEEDS:
        return {
            "status": "stub", "kind": "stub",
            "message": f"动作「{action}」尚未接线，需要：{_STUB_NEEDS[action]}",
            "truth_boundary": "本原型未实现该能力，未产生任何外部调用",
        }

    handler = _SINGLE.get(action)
    if handler is None:
        return {"status": "error", "message": f"未知动作：{action}"}

    ctx = objects[0]
    if len(objects) > 1:
        ctx = dict(ctx)
        ctx["_multi"] = [o["path"] for o in objects]
        ctx["_note"] = f"多选 {len(objects)} 个对象，本次只处理第一个"

    try:
        return handler(ctx)
    except RuntimeError as exc:
        # model 层与执行层的可预期错误，message 已经能直接给人看
        return {"status": "error", "kind": "model", "message": str(exc)}
    except Exception as exc:
        return {"status": "error", "kind": "local", "message": f"{type(exc).__name__}: {exc}"}
