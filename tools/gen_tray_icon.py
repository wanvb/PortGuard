#!/usr/bin/env python3
"""生成托盘图标 crates/portguard-win/assets/tray.ico。

不依赖 Pillow：手写 32x32 32bpp BGRA 位图，按 ICO 容器格式封装。
配色与 Web 面板一致（深底 + 亮蓝描边），保证托盘与面板视觉统一。

用法：python tools/gen_tray_icon.py
"""

import math
import os

SIZE = 32
# 与 web 面板 style.css 的主题色保持一致
BG = (0x11, 0x18, 0x23)      # --surface 深底
EDGE = (0x38, 0xBD, 0xF8)    # --accent 亮蓝描边
MARK = (0xE6, 0xED, 0xF3)    # --text 盾内对勾

SS = 4  # 每像素超采样倍数，用于抗锯齿


def shield_half_width(v):
    """给定归一化纵坐标 v（0 顶部），返回盾牌半宽；越界返回 -1。"""
    if v < 0.06 or v > 0.95:
        return -1.0
    hw = 0.42
    if v < 0.16:
        # 顶部圆角
        t = (0.16 - v) / 0.10
        hw *= math.sqrt(max(0.0, 1.0 - t * t))
    if v > 0.52:
        # 下半部收窄至尖
        hw *= 1.0 - (v - 0.52) / (0.95 - 0.52)
    return hw


def in_shield(u, v, inset=0.0):
    hw = shield_half_width(v)
    if hw < 0:
        return False
    return abs(u - 0.5) <= hw - inset


def in_mark(u, v):
    """盾牌内的对勾：两段线段加粗。"""
    for (x0, y0), (x1, y1) in (((0.30, 0.52), (0.44, 0.66)), ((0.44, 0.66), (0.71, 0.37))):
        dx, dy = x1 - x0, y1 - y0
        length2 = dx * dx + dy * dy
        t = ((u - x0) * dx + (v - y0) * dy) / length2
        t = max(0.0, min(1.0, t))
        px, py = x0 + t * dx, y0 + t * dy
        if math.hypot(u - px, v - py) <= 0.055:
            return True
    return False


def sample_class(u, v):
    """返回该点所属图层：0 透明 / 1 底色 / 2 描边 / 3 对勾。"""
    if not in_shield(u, v):
        return 0
    if in_mark(u, v):
        return 3
    # 内侧 1.5px 视为描边
    if not in_shield(u, v, inset=0.055):
        return 2
    return 1


def build_bgra():
    """逐像素超采样，返回自底向上的 BGRA 字节。"""
    rows = []
    for y in range(SIZE - 1, -1, -1):  # ICO 位图为 bottom-up
        row = bytearray()
        for x in range(SIZE):
            acc = [0.0, 0.0, 0.0, 0.0]  # r,g,b, alpha 权重
            for sy in range(SS):
                for sx in range(SS):
                    u = (x + (sx + 0.5) / SS) / SIZE
                    v = (y + (sy + 0.5) / SS) / SIZE
                    cls = sample_class(u, v)
                    if cls == 0:
                        continue
                    color = {1: BG, 2: EDGE, 3: MARK}[cls]
                    w = 1.0 / (SS * SS)
                    acc[0] += color[0] * w
                    acc[1] += color[1] * w
                    acc[2] += color[2] * w
                    acc[3] += w
            a = acc[3]
            if a <= 0:
                row += b"\x00\x00\x00\x00"
                continue
            # 按覆盖率还原颜色，避免边缘发暗
            r, g, b = acc[0] / a, acc[1] / a, acc[2] / a
            row += bytes((int(b + 0.5), int(g + 0.5), int(r + 0.5), int(a * 255 + 0.5)))
        rows.append(bytes(row))
    return b"".join(rows)


def build_ico(pixels):
    header = (
        b"\x00\x00"          # reserved
        b"\x01\x00"          # type = icon
        b"\x01\x00"          # count = 1
    )
    # BITMAPINFOHEADER：高度写两倍，因为格式上还要跟一张 AND 掩码
    info = (
        (40).to_bytes(4, "little")
        + SIZE.to_bytes(4, "little")
        + (SIZE * 2).to_bytes(4, "little")
        + (1).to_bytes(2, "little")
        + (32).to_bytes(2, "little")
        + (0).to_bytes(4, "little")   # BI_RGB
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
    )
    # AND 掩码：32 位一行 → 4 字节，全 0（透明度由 alpha 通道决定）
    mask = b"\x00" * (4 * SIZE)
    image = info + pixels + mask

    entry = (
        bytes((SIZE, SIZE, 0, 0))
        + (1).to_bytes(2, "little")
        + (32).to_bytes(2, "little")
        + len(image).to_bytes(4, "little")
        + (6 + 16).to_bytes(4, "little")
    )
    return header + entry + image


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = os.path.join(root, "crates", "portguard-win", "assets", "tray.ico")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "wb") as f:
        f.write(build_ico(build_bgra()))
    print("已生成", out, os.path.getsize(out), "字节")


if __name__ == "__main__":
    main()
