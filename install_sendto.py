"""把动作装进 Windows「发送到」菜单。

生成的快捷方式形如：
    发送到 ▸ Armory · 查看信息
点击后等价于：
    pythonw cli.py info <选中的路径...>

优点：零注册表写入、零安装、删掉 .lnk 即卸载。
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import router

HERE = Path(__file__).resolve().parent
PREFIX = "Armory · "


def pythonw() -> Path:
    """定位 pythonw.exe（无控制台窗口，右键点击不闪黑框）。"""
    exe = Path(sys.executable)
    candidate = exe.with_name("pythonw.exe")
    if candidate.exists():
        return candidate
    return exe


def build_script(items: list[tuple[str, str]]) -> str:
    """生成 PowerShell 脚本。items = [(快捷方式名, 动作名), ...]"""
    sendto = "%APPDATA%\\Microsoft\\Windows\\SendTo"
    lines = [
        "$ws = New-Object -ComObject WScript.Shell",
        f"$sendto = [Environment]::ExpandEnvironmentVariables('{sendto}')",
        f"$pyw = '{pythonw()}'",
        f"$cli = '{HERE / 'cli.py'}'",
        "",
    ]
    for name, action in items:
        lines += [
            f"$lnk = $ws.CreateShortcut(\"$sendto\\{PREFIX}{name}.lnk\")",
            "$lnk.TargetPath = $pyw",
            f"$lnk.Arguments = '\"' + $cli + '\" {action}'",
            f"$lnk.WorkingDirectory = '{HERE}'",
            "$lnk.Description = 'Armory 右键增强'",
            "$lnk.IconLocation = \"$pyw,0\"",
            "$lnk.Save()",
            f"Write-Output \"installed: {name}\"",
            "",
        ]
    return "\n".join(lines)


def run_ps1(script: str) -> subprocess.CompletedProcess:
    """PowerShell 5.1 只认带 BOM 的 UTF-8，中文文件名必须走这条路。"""
    tmp = Path(tempfile.gettempdir()) / "armory_sendto_install.ps1"
    tmp.write_text(script, encoding="utf-8-sig")
    return subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(tmp)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--with-stub", action="store_true",
                    help="连未接线的动作（总结/翻译/OCR…）一起装上")
    args = ap.parse_args()

    spec = router.load_actions()
    items = []
    for name, meta in spec["actions"].items():
        if meta["kind"] == "stub" and not args.with_stub:
            continue
        items.append((meta["label"], name))

    print(f"准备安装 {len(items)} 个动作到「发送到」菜单：")
    for label, action in items:
        print(f"  {PREFIX}{label}   ->  {action}")

    proc = run_ps1(build_script(items))
    print(proc.stdout or "")
    if proc.returncode != 0:
        print("安装失败：", proc.stderr, file=sys.stderr)
        return proc.returncode

    print("\n完成。在资源管理器里选中对象 → 右键 → 发送到，即可看到。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
