"""卸载：删掉 SendTo 目录里所有 Armory 快捷方式。干净彻底，不留注册表。"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

PREFIX = "Armory · "


def main() -> int:
    sendto = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "SendTo"
    if not sendto.is_dir():
        print("找不到 SendTo 目录：", sendto, file=sys.stderr)
        return 1

    targets = [p for p in sendto.iterdir()
               if p.suffix.lower() == ".lnk" and p.name.startswith(PREFIX)]

    if not targets:
        print("没有已安装的 Armory 快捷方式。")
        return 0

    for p in targets:
        print("移除：", p.name)
        p.unlink()

    # 清掉生成过的临时安装脚本
    tmp = Path(subprocess.os.environ.get("TEMP", ".")) / "armory_sendto_install.ps1"
    if tmp.exists():
        tmp.unlink()

    print(f"\n共移除 {len(targets)} 个。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
