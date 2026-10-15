#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""发布打包脚本：编译 64 / 32 位两个 exe，整理成可直接上传 GitHub Releases 的产物。

用法（在仓库根目录执行）：

    python tools/package_release.py

产物：

    dist/PortGuard.exe          x86_64-pc-windows-msvc
    dist/PortGuard_x32.exe      i686-pc-windows-msvc
    dist/ip2region_v4.xdb       地理位置库（可选，缺失只影响归属地展示）

说明：cargo 的产物名由 `[[bin]] name` 决定，无法按 target 改名，
因此 32 位 exe 只能在打包阶段重命名为 PortGuard_x32.exe。
"""

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"

# (rust target, 发布文件名)
TARGETS = [
    ("x86_64-pc-windows-msvc", "PortGuard.exe"),
    ("i686-pc-windows-msvc", "PortGuard_x32.exe"),
]


def build(target: str) -> Path:
    """编译单个目标，返回产物路径。编译失败直接退出，绝不产出半成品。"""
    exe_name = "PortGuard.exe"
    print(f"[构建] {target} ...")
    result = subprocess.run(
        ["cargo", "build", "--release", "--target", target],
        cwd=ROOT,
    )
    if result.returncode != 0:
        sys.exit(f"[失败] {target} 编译失败（退出码 {result.returncode}）")

    exe = ROOT / "target" / target / "release" / exe_name
    if not exe.is_file():
        sys.exit(f"[失败] 未找到编译产物：{exe}")
    return exe


def main() -> int:
    DIST.mkdir(exist_ok=True)

    for target, release_name in TARGETS:
        exe = build(target)
        dst = DIST / release_name
        shutil.copy2(exe, dst)
        print(f"[产物] {release_name}  <-  {target}  ({dst.stat().st_size} 字节)")

    # 地理库是可选项：缺失时程序照常运行，面板显示「未知」
    db = ROOT / "ip2region_v4.xdb"
    if db.is_file():
        shutil.copy2(db, DIST / db.name)
        print(f"[产物] {db.name}（可选，随包分发）")
    else:
        print("[提示] 仓库根目录没有 ip2region_v4.xdb，已跳过（不影响判定）")

    print(f"\n[完成] 发布目录：{DIST}")
    print("       上传 GitHub Releases 时选这两个 exe 即可：")
    for _, release_name in TARGETS:
        print(f"         dist/{release_name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
