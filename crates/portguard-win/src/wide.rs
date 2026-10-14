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
pub fn write_wide_fixed(dst: &mut [u16], s: &str) {
    if dst.is_empty() {
        return;
    }
    let mut n = 0;
    for u in s.encode_utf16() {
        // 留出最后一格放 NUL
        if n + 1 >= dst.len() {
            break;
        }
        dst[n] = u;
        n += 1;
    }
    dst[n] = 0;
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
        write_wide_fixed(&mut buf, "ABCDEFGHIJ");
        assert_eq!(buf[5], 0, "必须保留结尾 NUL");
        assert_eq!(from_wide_fixed(&buf), "ABCDE");
    }

    #[test]
    fn 定长写入正常内容() {
        let mut buf = [0u16; 16];
        write_wide_fixed(&mut buf, "记录 12 个");
        assert_eq!(from_wide_fixed(&buf), "记录 12 个");
    }

    #[test]
    fn 定长读写往返一致() {
        let mut buf = [0u16; 128];
        // 中文按 UTF-16 计为 1 个码元，不应被误截断
        write_wide_fixed(&mut buf, "PortGuard 正在保护本机");
        assert_eq!(from_wide_fixed(&buf), "PortGuard 正在保护本机");
    }

    #[test]
    fn 零长度缓冲不越界() {
        let mut buf: [u16; 0] = [];
        write_wide_fixed(&mut buf, "x");
        assert!(from_wide_fixed(&buf).is_empty());
    }
}
