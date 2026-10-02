"""把动作装进 Windows「发送到」菜单。

生成的快捷方式形如：
    发送到 ▸ Armory · 查看信息
点击后等价于：
    pythonw cli.py info <选中的路径...>

优点：零注册表写入、零安装、删掉 .lnk 即卸载。
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import router

HERE = Path(__file__).resolve().parent
PREFIX = "Armory · "

# 标签白名单。标签会被拼进 PowerShell 字符串与文件名，
# 不放行引号、$、`、分号和路径分隔符，避免配置数据变成可执行入口。
_LABEL_RE = re.compile(r"^[\w\u4e00-\u9fff·\- ]+$")

# 动作键同样会被拼进 PowerShell 字符串（$lnk.Arguments），必须一并校验。
# 第 2 轮审计抓到：只校验了 label，漏了 action。
_ACTION_RE = re.compile(r"^[a-z][a-z0-9_]*$")

# 这类目录下的解释器随时可能被应用自己清理掉，钉死它等于给右键功能埋定时炸弹
_FRAGILE_DIRS = (".workbuddy", "\\AppData\\Local\\Temp", "\\Temp\\", "scoop\\apps")


def pythonw() -> Path:
    """定位 pythonw.exe（无控制台窗口，右键点击不闪黑框）。

    找不到就明确报错。曾经兜底退回 python.exe，与「不闪黑框」的设计前提相悖。
    """
    exe = Path(sys.executable)
    candidate = exe.with_name("pythonw.exe")
    if not candidate.exists():
        raise SystemExit(
            f"找不到 pythonw.exe（{candidate}）。\n"
            "右键入口必须用 pythonw，否则每次点击都会闪一个控制台窗口。\n"
            "请换用带 pythonw 的 Python 安装，或手动指定后重试。"
        )
    return candidate


def _warn_if_fragile(path: Path) -> None:
    text = str(path)
    hit = next((d for d in _FRAGILE_DIRS if d in text), None)
    if hit:
        print(f"  [提醒] 解释器位于可被外部清理的目录（匹配 {hit}）：\n         {path}")
        print("         该目录的存留不由本项目控制，被清理后 10 个右键动作会静默失效，")
        print("         届时重跑本脚本即可恢复。")


def _ps_single(value: str) -> str:
    """PowerShell 单引号字符串：内部单引号写成两个。"""
    return "'" + value.replace("'", "''") + "'"


def _check_label(label: str) -> str:
    if not _LABEL_RE.match(label) or ".." in label:
        raise SystemExit(f"动作标签含不安全字符，已拒绝安装：{label!r}")
    return label


def _check_action(action: str) -> str:
    if not _ACTION_RE.match(action):
        raise SystemExit(f"动作键含不安全字符，已拒绝安装：{action!r}")
    return action


def build_script(items: list[tuple[str, str]]) -> str:
    """生成 PowerShell 脚本。items = [(快捷方式名, 动作名), ...]"""
    lines = [
        "$ErrorActionPreference = 'Stop'",
        "$ws = New-Object -ComObject WScript.Shell",
        "$sendto = [Environment]::ExpandEnvironmentVariables("
        + _ps_single("%APPDATA%\\Microsoft\\Windows\\SendTo") + ")",
        f"$pyw = {_ps_single(str(pythonw()))}",
        f"$cli = {_ps_single(str(HERE / 'cli.py'))}",
        f"$work = {_ps_single(str(HERE))}",
        "",
    ]
    for name, action in items:
        lines += [
            f"$lnk = $ws.CreateShortcut((Join-Path $sendto {_ps_single(PREFIX + name + '.lnk')}))",
            "$lnk.TargetPath = $pyw",
            f"$lnk.Arguments = '\"' + $cli + '\" {action}'",
            "$lnk.WorkingDirectory = $work",
            "$lnk.Description = 'Armory 右键增强'",
            "$lnk.IconLocation = \"$pyw,0\"",
            "$lnk.Save()",
            f"Write-Output \"installed: {name}\"",
            "",
        ]
    return "\n".join(lines)


def run_ps1(script: str) -> subprocess.CompletedProcess:
    """PowerShell 5.1 只认带 BOM 的 UTF-8，中文文件名必须走这条路。

    临时文件用随机名并在 finally 里删掉，不在 %TEMP% 留一份含本机绝对路径的固定文件。
    """
    fd, tmp_path = tempfile.mkstemp(suffix=".ps1", prefix="armory_sendto_")
    try:
        os.close(fd)
        Path(tmp_path).write_text(script, encoding="utf-8-sig")
        return subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-File", tmp_path],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
    finally:
        try:
            Path(tmp_path).unlink()
        except OSError:
            pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--with-stub", action="store_true",
                    help="连尚未接线的动作（当前只有 audit、rename）一起装上")
    args = ap.parse_args()

    spec = router.load_actions()
    items = []
    for name, meta in spec["actions"].items():
        if meta["kind"] == "stub" and not args.with_stub:
            continue
        items.append((_check_label(meta["label"]), _check_action(name)))

    print(f"准备安装 {len(items)} 个动作到「发送到」菜单：")
    for label, action in items:
        print(f"  {PREFIX}{label}   ->  {action}")

    _warn_if_fragile(pythonw())

    proc = run_ps1(build_script(items))
    print(proc.stdout or "")
    if proc.returncode != 0:
        print("安装失败：", proc.stderr, file=sys.stderr)
        return proc.returncode

    print("\n完成。在资源管理器里选中对象 → 右键 → 发送到，即可看到。")
    print("升级或更换 Python 后，重跑本脚本即可。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
