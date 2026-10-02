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

# 大小闸门。detector 已经算好了 size_bytes，这里必须真的用它，不能只是摆设。
LOCAL_MAX_BYTES = 50 << 20    # 本地动作：50MB
MODEL_MAX_BYTES = 2 << 20     # 送模型：2MB，超出既慢又烧额度

# 视觉模型只认这几种。svg/psd/raw/heic/ico 喂过去只会报错。
VISION_MIME = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".gif": "image/gif",
}


def _gate_size(ctx: dict, limit: int, what: str) -> dict | None:
    size = ctx.get("size_bytes") or 0
    if size > limit:
        return {"status": "error", "kind": "local",
                "message": f"{what}：文件 {size / 1048576:.1f}MB 超过上限 "
                           f"{limit / 1048576:.0f}MB，已跳过（避免卡死右键）"}
    return None

# ---------------------------------------------------------------------------
# local handlers
# ---------------------------------------------------------------------------


def _h_info(ctx: dict) -> dict:
    """生成可读摘要。

    曾经只是把 ctx 原样回给调用方，剪贴板里什么都没有，而动作描述还写着
    「含 SHA-256」——描述与实际对不上。现在摘要里有的字段才写。
    """
    lines = [f"# 信息：{ctx['name']}", "",
             f"- 类型：{ctx.get('type_label', '未知')}",
             f"- 路径：`{ctx.get('path')}`"]

    if not ctx.get("exists"):
        lines.append("- 状态：路径不存在")
        return {"status": "ok", "kind": "local", "clipboard": "\n".join(lines), "data": ctx}

    size = ctx.get("size_bytes")
    if size is not None:
        lines.append(f"- 大小：{size:,} 字节（{size / 1024:.1f} KB）")
    if ctx.get("modified"):
        lines.append(f"- 修改时间：{ctx['modified']}")
    if ctx.get("extension"):
        lines.append(f"- 扩展名：`{ctx['extension']}`")

    if ctx.get("file_count") is not None:
        tail = "（已截断统计）" if ctx.get("truncated") else ""
        lines.append(f"- 文件数：{ctx['file_count']}{tail}")
        if ctx.get("top_extensions"):
            lines.append("")
            lines.append("## 扩展名分布")
            lines += [f"- `{e}` × {n}" for e, n in ctx["top_extensions"]]

    if ctx.get("line_count") is not None:
        lines.append(f"- 行数：{ctx['line_count']}")

    if ctx.get("preview"):
        lines += ["", "## 预览", "```", ctx["preview"], "```"]

    lines += ["", "- SHA-256：本动作不计算；需要请用「复制 SHA-256」"]
    return {"status": "ok", "kind": "local", "clipboard": "\n".join(lines), "data": ctx}


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
    blocked = _gate_size(ctx, LOCAL_MAX_BYTES, "提取代码结构")
    if blocked:
        return blocked

    path = Path(ctx["path"])
    defs: list[str] = []
    imports: list[str] = []
    line_count = 0

    try:
        # 逐行流式扫描。曾经整文件读进内存再跑两次全文正则，33MB 输入峰值 121MB；
        # 改成 chunks 攒完再 join 更是涨到 153MB（等于全文进内存还多一份）。
        # 现在内存占用与文件大小无关。
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line_count += 1
                if len(line) > 1 << 20:      # 单行超 1MB（压缩过的巨型 JSON）不参与匹配
                    continue
                m = _DEF_RE.match(line)
                if m:
                    defs.append(m.group(1))
                    continue
                m = _IMPORT_RE.match(line)
                if m:
                    imports.append(m.group(0).strip()[:100])
    except OSError as exc:
        return {"status": "error", "kind": "local", "message": f"读取失败：{exc}"}

    lines = [
        f"# 结构：{path.name}", "",
        f"- 总行数：{line_count}",
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


def _read_for_model(ctx: dict, limit: int = 0) -> tuple[str, int]:
    """送模型前的五道闸门：大小、是否纯文本、是否敏感文件、读多少、内容脱敏。

    返回 (正文, 脱敏处数)。

    少了第三道会出真事故：用户右键「总结」自己的凭据或配置文件，明文内容会
    原样发往第三方模型。这类文件往往只有几 KB，体积闸门根本拦不住，
    只能靠文件名判据。
    """
    blocked = _gate_size(ctx, MODEL_MAX_BYTES, "送模型")
    if blocked:
        raise RuntimeError(blocked["message"].split("：", 1)[-1])

    path = Path(ctx["path"])

    if detector.is_sensitive_path(str(path)):
        raise RuntimeError(
            "拒绝发送：这个文件名看起来装着凭据或配置（key / secret / token / .env / "
            "config.json / .pem / id_rsa …）。\n"
            "「总结」「翻译」会把正文原样发给第三方模型，等于把钥匙交出去。\n"
            "确实要处理，请先人工复制需要的片段到一个普通文件里再右键。"
        )

    if not detector.looks_text_path(str(path)):
        raise RuntimeError(
            "文件内容不是纯文本（检测到二进制字节）。本原型不支持 PDF / Word / Excel / "
            "EPUB 等格式的正文抽取，需要专用抽取器，不送模型以免烧额度换幻觉。"
        )

    if not limit:
        limit = int(model.load_config().get("max_input_chars", 6000))

    # 只读需要的量，不把整个文件读进内存
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read(limit)
    if not raw.strip():
        raise RuntimeError("文件内容为空，没什么可处理的")

    # 不是敏感文件名，内容里也可能夹着凭据，照样抹掉
    raw, redacted = detector.redact(raw)
    if len(raw) >= limit:
        raw += f"\n\n……（已截断至前 {limit} 字符）"
    return raw, redacted


def _h_summarize(ctx: dict) -> dict:
    text, redacted = _read_for_model(ctx)
    out = model.chat(_SUMMARY_SYS, f"文件：{ctx['name']}\n\n{text}", max_tokens=2000)
    body = f"# 总结：{ctx['name']}\n\n{out}"
    if redacted:
        body += f"\n\n> 发送前已抹掉 {redacted} 处疑似凭据"
    return {"status": "ok", "kind": "model", "clipboard": body,
            "data": {"model": model.load_config().get("model"),
                     "redacted": redacted, "egress": True}}


def _h_translate(ctx: dict) -> dict:
    # 翻译送全文既慢又烧额度，且长输入会诱出推理模型的思考过程，单独压到 3000 字符
    text, redacted = _read_for_model(ctx, limit=3000)
    out = model.chat(_TRANSLATE_SYS, text, max_tokens=3000)
    if redacted:
        out += f"\n\n> 发送前已抹掉 {redacted} 处疑似凭据"
    return {"status": "ok", "kind": "model", "clipboard": out,
            "data": {"model": model.load_config().get("model"),
                     "redacted": redacted, "egress": True}}


def _h_describe(ctx: dict) -> dict:
    """两步：视觉模型出描述（中文能力弱，常给英文）→ 文本模型译中文。

    为什么不直接用大视觉模型出中文：实测 90b 视觉要走 60 秒以上，右键等不起。
    11b 视觉约 7 秒，加一步 3 秒翻译，总共 10 秒出中文，划算。
    """
    ext = Path(ctx["path"]).suffix.lower()
    if ext not in VISION_MIME:
        return {"status": "error", "kind": "model",
                "message": f"图片描述不支持 {ext or '无扩展名'} 格式，"
                           f"当前仅支持 {', '.join(sorted(VISION_MIME))}"}
    blocked = _gate_size(ctx, MODEL_MAX_BYTES, "图片描述")
    if blocked:
        return blocked

    raw = model.vision(
        ctx["path"],
        "Describe this image: what is the subject, what text or UI elements are visible, "
        "and what it might be used for. Be factual, no more than 6 sentences. "
        "Do not invent details you cannot see.",
        max_tokens=600,
        mime=VISION_MIME[ext],
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
