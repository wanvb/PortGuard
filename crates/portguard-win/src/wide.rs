//! UTF-16 字符串工具。
//!
//! Windows 的 `W` 系列 API 全部要求以 NUL 结尾的 UTF-16 缓冲区，
//! 且缓冲区必须比调用存活得更久。集中在这里处理，避免各处重复构造。

/// 转换为带结尾 NUL 的 UTF-16 缓冲区。
pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 把字符串写入定长 UTF-16 数组（自动截断并保证 NUL 结尾）。
///
/// 用于 `NOTIFYICONDATAW::szTip` 这类内嵌定长字段。
///
/// 参数是**指向数组字段的裸指针**而不是 `&mut [u16]`：32 位目标（`x86`）下
/// `windows` crate 把 `NOTIFYICONDATAW` 声明为 `#[repr(C, packed(1))]`，
/// 对其字段取引用会直接编译失败（E0793，未对齐引用属 UB）。
/// 调用方一律用 `core::ptr::addr_of_mut!` 取指针，本函数再用 `write_unaligned`
/// 逐元素写入，既不构造引用，也不要求内存对齐。
///
/// # Safety
///
/// `field` 必须指向调用方独占、且在调用期间无人借用的可写内存，长度不少于 `N` 个 `u16`。
pub unsafe fn write_wide_field<const N: usize>(field: *mut [u16; N], s: &str) {
    if N == 0 {
        return;
    }
    let dst = field.cast::<u16>();
    let mut n = 0;
    for u in s.encode_utf16() {
        // 留出最后一格放 NUL
        if n + 1 >= N {
            break;
        }
        dst.add(n).write_unaligned(u);
        n += 1;
    }
    dst.add(n).write_unaligned(0);
}

/// 把定长 UTF-16 数组读回字符串（截断到第一个 NUL）。
pub fn from_wide_fixed(src: &[u16]) -> String {
    let end = src.iter().position(|&c| c == 0).unwrap_or(src.len());
    String::from_utf16_lossy(&src[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 转换后以零结尾() {
        let w = to_wide("PortGuard");
        assert_eq!(w.last(), Some(&0));
        assert_eq!(w.len(), 9 + 1);
    }

    #[test]
    fn 空串转换只有一个零() {
        assert_eq!(to_wide(""), vec![0u16]);
    }

    #[test]
    fn 定长写入超长时截断且仍以零结尾() {
        let mut buf = [0u16; 6];
        unsafe { write_wide_field(core::ptr::addr_of_mut!(buf), "ABCDEFGHIJ") };
        assert_eq!(buf[5], 0, "必须保留结尾 NUL");
        assert_eq!(from_wide_fixed(&buf), "ABCDE");
    }

    #[test]
    fn 定长写入正常内容() {
        let mut buf = [0u16; 16];
        unsafe { write_wide_field(core::ptr::addr_of_mut!(buf), "记录 12 个") };
        assert_eq!(from_wide_fixed(&buf), "记录 12 个");
    }

    #[test]
    fn 定长读写往返一致() {
        let mut buf = [0u16; 128];
        // 中文按 UTF-16 计为 1 个码元，不应被误截断
        unsafe { write_wide_field(core::ptr::addr_of_mut!(buf), "PortGuard 正在保护本机") };
        assert_eq!(from_wide_fixed(&buf), "PortGuard 正在保护本机");
    }

    #[test]
    fn 零长度缓冲不越界() {
        let mut buf: [u16; 0] = [];
        unsafe { write_wide_field(core::ptr::addr_of_mut!(buf), "x") };
        assert!(from_wide_fixed(&buf).is_empty());
    }

    #[test]
    fn 未对齐字段也能写入() {
        // 模拟 `#[repr(C, packed(1))]` 结构体里的 u16 数组：起始地址必定是奇数。
        #[repr(C, packed(1))]
        struct Packed {
            _pad: u8,
            text: [u16; 8],
        }
        let mut p = Packed {
            _pad: 0,
            text: [0; 8],
        };
        unsafe { write_wide_field(core::ptr::addr_of_mut!(p.text), "ok") };
        // 读回同样不能对 packed 字段取引用，故走裸指针 + read_unaligned。
        let raw = core::ptr::addr_of!(p.text).cast::<u16>();
        let back: Vec<u16> = (0..8)
            .map(|i| unsafe { raw.add(i).read_unaligned() })
            .collect();
        assert_eq!(from_wide_fixed(&back), "ok");
    }
}
