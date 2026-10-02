"""SendTo 入口。

用法：pythonw cli.py <action> <path> [path...]
SendTo 会把选中的文件路径自动追加到命令行尾部。

结果三件套：落 evidence + 写剪贴板 + 弹系统通知。
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

import router

HERE = Path(__file__).resolve().parent
NOTIFY = HERE / "notify.ps1"


def set_clipboard(text: str) -> bool:
    """经临时文件写剪贴板，绕开命令行转义与 GBK 编码问题。"""
    try:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(text)
            tmp_path = tmp.name
        subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
             f"Set-Clipboard -Value (Get-Content -Raw -Encoding UTF8 '{tmp_path}')"],
            check=False, timeout=15,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return True
    except Exception:
        return False


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


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        notify("Armory", "缺少动作参数")
        return 2

    action = argv[1]
    paths = argv[2:]
    if not paths:
        notify("Armory", "没有选中任何对象")
        return 2

    # 模型动作要等几秒到几十秒，先给个回执，否则右键点了像卡死
    meta = router.load_actions()["actions"].get(action, {})
    if meta.get("kind") == "model":
        notify(f"Armory · {meta.get('label', action)}", "正在处理，完成后会再通知你…")

    out = router.route(action, paths)
    result = out.get("result", {})

    # 结果呈现：优先动作自带的 clipboard 内容，否则给一句状态摘要
    if result.get("clipboard"):
        set_clipboard(result["clipboard"])
        summary = f"已写入剪贴板 · {len(result['clipboard'])} 字符"
    else:
        summary = result.get("message") or f"状态：{out.get('status')}"

    ev = out.get("evidence", {})
    notify(f"Armory · {action}", f"{summary}\nevidence: {ev.get('evidence_path', '-')}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
