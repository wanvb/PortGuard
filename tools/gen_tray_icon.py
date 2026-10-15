#!/usr/bin/env python3
"""生成托盘 / 程序图标 crates/portguard-win/assets/tray.ico。

不依赖 Pillow：手写 32bpp BGRA 位图，按 ICO 容器格式封装。
配色与 Web 面板一致（深底 + 亮蓝描边），保证托盘与面板视觉统一。

同一份 ico 有两条使用路径：
- 运行时：`portguard-win` 用 include_bytes! 内嵌，写临时文件后 LoadImageW 加载到托盘；
- 编译时：`portguard-app/build.rs` 调用 rc.exe 把它作为 RT_GROUP_ICON 资源写进 exe，
  使 PortGuard.exe 自身（资源管理器、任务管理器、控制台窗口）也显示该图标。

尺寸策略：16/32/48 用未压缩 BMP 条目（托盘与常规图标视图），
256 用 PNG 压缩条目（资源管理器超大图标），避免未压缩 256 撑大 exe 近 270 KB。

用法：python tools/gen_tray_icon.py
"""

import math
import os
import struct
import zlib

# 与 web 面板 style.css 的主题色保持一致
BG = (0x11, 0x18, 0x23)      # --surface 深底
EDGE = (0x38, 0xBD, 0xF8)    # --accent 亮蓝描边
MARK = (0xE6, 0xED, 0xF3)    # --text 盾内对勾

SIZES = (16, 32, 48, 256)    # 覆盖托盘小图标到资源管理器超大图标
SS = 4                       # 每像素超采样倍数，用于抗锯齿


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
    # 内侧约 2px（32 尺寸下）视为描边
    if not in_shield(u, v, inset=0.055):
        return 2
    return 1


def build_rgba(size):
    """逐像素超采样，返回自上而下的 RGBA 字节（PNG 条目直接可用）。"""
    rows = bytearray()
    for y in range(size):
        for x in range(size):
            acc = [0.0, 0.0, 0.0, 0.0]  # r,g,b, alpha 权重
            for sy in range(SS):
                for sx in range(SS):
                    u = (x + (sx + 0.5) / SS) / size
                    v = (y + (sy + 0.5) / SS) / size
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
                rows += b"\x00\x00\x00\x00"
                continue
            # 按覆盖率还原颜色，避免边缘发暗
            r, g, b = acc[0] / a, acc[1] / a, acc[2] / a
            rows += bytes((int(r + 0.5), int(g + 0.5), int(b + 0.5), int(a * 255 + 0.5)))
    return bytes(rows)


def build_bmp(size, rgba):
    """ICO 的 BMP 条目：BITMAPINFOHEADER + 自底向上 BGRA + AND 掩码。"""
    pixels = bytearray()
    for y in range(size - 1, -1, -1):  # ICO 位图为 bottom-up
        row = rgba[y * size * 4:(y + 1) * size * 4]
        for x in range(size):
            r, g, b, a = row[x * 4:x * 4 + 4]
            pixels += bytes((b, g, r, a))

    info = struct.pack(
        "<IiiHHIIiiII",
        40,                 # biSize
        size,               # biWidth
        size * 2,           # biHeight：格式上还要跟一张 AND 掩码，故写两倍
        1,                  # biPlanes
        32,                 # biBitCount
        0,                  # BI_RGB
        0, 0, 0, 0, 0,
    )
    # AND 掩码：32 位一行 → 每行按 4 字节对齐，全 0（透明度由 alpha 通道决定）
    mask = b"\x00" * (((size + 31) // 32) * 4 * size)
    return info + bytes(pixels) + mask


def png_chunk(tag, data):
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))


def build_png(size, rgba):
    """ICO 的 PNG 条目：Vista 及以上支持，256 尺寸用它可省下约 250 KB。"""
    raw = bytearray()
    for y in range(size):
        raw.append(0)  # 每行过滤器类型：None
        raw += rgba[y * size * 4:(y + 1) * size * 4]
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)  # 8 位 RGBA
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + png_chunk(b"IEND", b"")
    )


def build_ico():
    images = []
    for size in SIZES:
        rgba = build_rgba(size)
        # 大尺寸走 PNG，小尺寸走未压缩 BMP（兼容性最好）
        images.append((size, build_png(size, rgba) if size >= 256 else build_bmp(size, rgba)))

    header = b"\x00\x00" + b"\x01\x00" + struct.pack("<H", len(images))
    offset = 6 + 16 * len(images)
    entries = bytearray()
    body = bytearray()
    for size, data in images:
        # 目录里 256 需写成 0
        dim = 0 if size >= 256 else size
        entries += bytes((dim, dim, 0, 0))
        entries += struct.pack("<HHII", 1, 32, len(data), offset)
        body += data
        offset += len(data)
    return header + bytes(entries) + bytes(body)


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = os.path.join(root, "crates", "portguard-win", "assets", "tray.ico")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    data = build_ico()
    with open(out, "wb") as f:
        f.write(data)
    print("已生成", out, len(data), "字节，尺寸", list(SIZES))


if __name__ == "__main__":
    main()
