"""SendTo 入口。

用法：pythonw cli.py <action> <path> [path...]
SendTo 会把选中的文件路径自动追加到命令行尾部。

结果三件套：落 evidence + 写剪贴板 + 弹系统通知。
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path

import model
import router

HERE = Path(__file__).resolve().parent
NOTIFY = HERE / "notify.ps1"
SLOW_LOCAL_BYTES = 8 << 20   # 本地动作：单文件超过这个体积就先发回执
SLOW_DIR_ENTRIES = 2000      # 本地动作：目录直接子项超过这个数也先发回执


def set_clipboard(text: str) -> bool:
    """经临时文件写剪贴板，绕开命令行转义与 GBK 编码问题。

    必须看返回码。曾经无条件 return True，导致 RDP 会话、剪贴链被锁、
    powershell 不在 PATH 时，用户看到「已写入剪贴板」而剪贴板其实是空的——
    这种静默假成功比明确失败更伤信任。
    """
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(text)
            tmp_path = tmp.name
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
             f"Set-Clipboard -Value (Get-Content -Raw -Encoding UTF8 '{tmp_path}')"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            check=False, timeout=15,
        )
        if proc.returncode != 0:
            print("clipboard failed:", (proc.stderr or "").strip()[:200], file=sys.stderr)
            return False
        return True
    except Exception as exc:
        print(f"clipboard failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return False
    finally:
        if tmp_path:
            try:
                Path(tmp_path).unlink()
            except OSError:
                pass


def notify(title: str, text: str) -> None:
    if not NOTIFY.exists():
        return
    try:
        subprocess.Popen(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-File", str(NOTIFY), title, text[:240]],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def _human_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1048576:.1f} MB"


def _egress_host() -> str:
    """外发动作要写清「发到哪」。拿不到就直说拿不到，不编一个主机名。"""
    try:
        url = model.load_config().get("base_url", "")
        return urllib.parse.urlparse(url).hostname or url or "未知主机"
    except Exception:
        return "未知主机"


def _egress_notice(paths: list[str]) -> str:
    """外发动作的第一条通知：说清「什么、多大、发给谁」。

    第 4 轮 M-8：图片外发的敏感名单是先天弱的——人给截图起名是
    `prod-keys-screenshot.png`、`Snipaste-2.png` 这种形状，规则要求凭据词
    紧贴扩展名，抓不到。文本路有内容脱敏兜底，图片路没有。名单堵不上就换
    控制点：让用户在东西出门之前看见「即将上传 X 到 Y」。看得见才谈得上同意。
    """
    names = []
    for p in paths[:3]:
        try:
            size = os.path.getsize(p) if os.path.isfile(p) else None
        except OSError:
            size = None
        name = Path(p).name or p
        names.append(f"{name}（{_human_size(size)}）" if size is not None else name)
    tail = f" 等 {len(paths)} 个" if len(paths) > 3 else ""
    return f"即将上传 {', '.join(names)}{tail} → {_egress_host()}"


def _is_slow(paths: list[str]) -> bool:
    """本地动作要不要先发回执。

    文件夹也算：右键一个大目录跑 index，遍历 5000 个文件要几秒，是所有动作里
    最像卡死的一种，而上一版判定用 `os.path.isfile`，它永远返回 False
    （第 4 轮 M-4 漏项）。
    """
    for p in paths:
        try:
            if os.path.isfile(p):
                if os.path.getsize(p) > SLOW_LOCAL_BYTES:
                    return True
            elif os.path.isdir(p):
                # 只数一层，不递归——递归本身就够慢了，还怎么用快慢决定要不要发回执
                n = 0
                with os.scandir(p) as it:
                    for _ in it:
                        n += 1
                        if n > SLOW_DIR_ENTRIES:
                            return True
        except OSError:
            continue
    return False


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        notify("Armory", "缺少动作参数")
        return 2

    action = argv[1]
    paths = argv[2:]
    if not paths:
        notify("Armory", "没有选中任何对象")
        return 2

    # 先给回执，否则右键点了像卡死。
    # 不只是模型动作：33MB 的本地文件跑 outline 要 4 秒多，大目录跑 index 同理。
    meta = router.load_actions()["actions"].get(action, {})
    if meta.get("egress"):
        # 外发动作的第一条通知必须写清「什么、多大、发给谁」，不能只说"正在处理"
        notify(f"Armory · {meta.get('label', action)}", _egress_notice(paths))
    elif meta.get("kind") == "model" or _is_slow(paths):
        notify(f"Armory · {meta.get('label', action)}", "正在处理，完成后会再通知你…")

    out = router.route(action, paths, trusted=True)
    result = out.get("result", {})

    # 结果呈现：优先动作自带的 clipboard 内容，否则给一句状态摘要
    if result.get("clipboard"):
        ok = set_clipboard(result["clipboard"])
        summary = (f"已写入剪贴板 · {len(result['clipboard'])} 字符" if ok
                   else f"结果已生成但写入剪贴板失败（{len(result['clipboard'])} 字符，见 evidence）")
    else:
        summary = result.get("message") or f"状态：{out.get('status')}"

    ev = out.get("evidence", {})
    notify(f"Armory · {action}", f"{summary}\nevidence: {ev.get('evidence_path', '-')}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
