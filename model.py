"""模型接入层 —— 可插拔 OpenAI 兼容客户端。

零第三方依赖，用 urllib。配置优先级：
    环境变量 ARMORY_LLM_*  >  model_config.json

没配就是没配，明确返回未配置，绝不假装调用成功。
"""
from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG_FILE = HERE / "model_config.json"

DEFAULTS = {
    "provider": "openai-compatible",
    "base_url": "",
    "api_key": "",
    "model": "",
    "vision_model": "",
    "timeout": 90,
    "max_input_chars": 6000,
}


_cfg_cache: dict | None = None


def load_config(force: bool = False) -> dict:
    """配置缓存。一次右键动作里不该反复读盘解析。"""
    global _cfg_cache
    if _cfg_cache is not None and not force:
        return _cfg_cache

    cfg = dict(DEFAULTS)

    if CONFIG_FILE.exists():
        try:
            cfg.update(json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError) as exc:
            cfg["_load_error"] = f"{type(exc).__name__}: {exc}"

    # 环境变量覆盖（key 不落盘的首选方式）
    env_map = {
        "base_url": "ARMORY_LLM_BASE_URL",
        "api_key": "ARMORY_LLM_API_KEY",
        "model": "ARMORY_LLM_MODEL",
        "vision_model": "ARMORY_LLM_VISION_MODEL",
    }
    for key, var in env_map.items():
        val = os.environ.get(var, "").strip()
        if val:
            cfg[key] = val

    _cfg_cache = cfg
    return cfg


def status() -> dict:
    """给外部查询：模型通不通，缺什么。"""
    cfg = load_config()
    missing = [k for k in ("base_url", "api_key", "model") if not cfg.get(k)]

    out = {
        "configured": not missing,
        "missing": missing,
        "base_url": cfg.get("base_url", ""),
        "model": cfg.get("model", ""),
        "vision_model": cfg.get("vision_model", ""),
        "source": "env" if os.environ.get("ARMORY_LLM_API_KEY") else
                  ("file" if CONFIG_FILE.exists() else "none"),
    }
    if cfg.get("_load_error"):
        out["config_error"] = cfg["_load_error"]
    return out


def _post(cfg: dict, payload: dict) -> dict:
    url = cfg["base_url"].rstrip("/") + "/chat/completions"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {cfg['api_key']}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=int(cfg.get("timeout", 90))) as resp:
        return json.loads(resp.read().decode("utf-8"))


def chat(system: str, user: str, max_tokens: int = 1500, model: str = "") -> str:
    """普通对话。抛出 RuntimeError 时 message 已是可直接展示的原因。

    推理模型会先用掉几百 token 思考，再产出正文。max_tokens 给小了会出现
    「思考完了但正文没生成」，所以正文为空时自动翻倍重试一次。
    """
    cfg = load_config()
    if not cfg.get("base_url") or not cfg.get("api_key") or not cfg.get("model"):
        miss = status()["missing"]
        raise RuntimeError(f"模型未配置，缺：{', '.join(miss)}。填 model_config.json 或设环境变量 ARMORY_LLM_*")

    payload = {
        "model": model or cfg["model"],
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.3,
        "max_tokens": max_tokens,
    }
    try:
        return _first_content(_post(cfg, payload))
    except _EmptyContent:
        payload["max_tokens"] = max_tokens * 3
        try:
            return _first_content(_post(cfg, payload))
        except _EmptyContent as exc:
            raise RuntimeError(
                f"模型只产出了思考过程，没产出正文（{exc}）。"
                "通常是推理链太长吃光了 token 预算，可换非推理模型或减小输入。"
            )


class _EmptyContent(Exception):
    """正文为空。通常不是模型坏了，而是推理过程把 max_tokens 预算吃光了。"""


def _first_content(data: dict) -> str:
    """只认 content 当正文。

    reasoning_content 是思考过程，不是答案——绝不拿它顶替。
    content 为空就抛 _EmptyContent，交给上层翻倍 max_tokens 重试。
    """
    try:
        msg = data["choices"][0]["message"]
    except (KeyError, IndexError, TypeError):
        raise RuntimeError(f"模型返回格式异常：{json.dumps(data, ensure_ascii=False)[:300]}")

    val = msg.get("content")
    if isinstance(val, str) and val.strip():
        return val.strip()

    raise _EmptyContent(f"finish_reason={data.get('choices', [{}])[0].get('finish_reason')}")


def vision(image_path: str, prompt: str, max_tokens: int = 1200,
           mime: str = "image/png") -> str:
    """视觉模型调用。需要配置 vision_model，否则报未配置。

    mime 必须按真实后缀传。曾经恒写 image/png，拿 jpg 也会发 png 头。
    """
    cfg = load_config()
    if not cfg.get("vision_model"):
        raise RuntimeError("未配置 vision_model，图片描述不可用（普通模型看不了图）")

    with open(image_path, "rb") as fh:
        b64 = base64.b64encode(fh.read()).decode("ascii")

    payload = {
        "model": cfg["vision_model"],
        "messages": [{
            "role": "user",
            "content": [
                {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{b64}"}},
                {"type": "text", "text": prompt},
            ],
        }],
        "max_tokens": max_tokens,
    }
    try:
        return _first_content(_post(cfg, payload))
    except _EmptyContent:
        payload["max_tokens"] = max_tokens * 3
        return _first_content(_post(cfg, payload))


def clip(text: str, limit: int) -> str:
    """超长输入截断，避免一次请求烧掉整篇长文。"""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n\n……（原文已截断，实际 {len(text)} 字符，送入模型 {limit} 字符）"
