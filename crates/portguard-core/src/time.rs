//! 时间工具。
//!
//! 核心逻辑全部使用「Unix 纪元毫秒」的 `u64` 时间戳，不使用 `SystemTime`，
//! 目的是让规则引擎、连接跟踪器完全可注入时间、可单元测试。

use std::time::{SystemTime, UNIX_EPOCH};

/// 当前 Unix 纪元毫秒。系统时钟早于 1970 时返回 0，不 panic。
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 默认时区偏移：UTC+8（中国标准时间），单位分钟。
pub const DEFAULT_UTC_OFFSET_MINUTES: i32 = 8 * 60;

/// 把 Unix 纪元毫秒格式化为 `YYYY-MM-DD HH:MM:SS`（按 UTC+8）。
///
/// Win7 兼容优先，不引入 chrono / time 等重型依赖，用纯整数运算实现
/// 民用历法换算（Howard Hinnant 算法）。
pub fn format_ms(ms: u64) -> String {
    format_ms_with_offset(ms, DEFAULT_UTC_OFFSET_MINUTES)
}

/// 按指定时区偏移（分钟）格式化时间。
///
/// 需要真实本机时区时，由 `portguard-win` 通过 Win32 API 取偏移后传入。
pub fn format_ms_with_offset(ms: u64, offset_minutes: i32) -> String {
    let secs = (ms / 1000) as i64 + offset_minutes as i64 * 60;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// 把「距离今天零点的天数」换算为民用日期 `(年, 月, 日)`。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 纪元零点换算正确() {
        assert!(format_ms(0).starts_with("1970-01-01"));
    }

    #[test]
    fn 已知时间点换算正确() {
        // 1_791_907_200_000 ms == 2026-10-13 16:00:00 UTC == 2026-10-14 00:00:00 UTC+8
        assert_eq!(format_ms(1_791_907_200_000), "2026-10-14 00:00:00");
    }

    #[test]
    fn 闰年二月正确处理() {
        // 1_709_136_000_000 ms == 2024-02-28 16:00:00 UTC == 2024-02-29 00:00:00 UTC+8
        assert_eq!(format_ms(1_709_136_000_000), "2024-02-29 00:00:00");
    }

    #[test]
    fn 时区偏移可配置() {
        let ms = 1_791_907_200_000u64;
        // 同一时刻，按 UTC 显示
        assert_eq!(format_ms_with_offset(ms, 0), "2026-10-13 16:00:00");
        // 按 UTC-5 显示
        assert_eq!(format_ms_with_offset(ms, -300), "2026-10-13 11:00:00");
    }

    #[test]
    fn 跨年边界正确() {
        // 1_735_689_600_000 ms == 2025-01-01 00:00:00 UTC == 2025-01-01 08:00:00 UTC+8
        assert_eq!(format_ms(1_735_689_600_000), "2025-01-01 08:00:00");
        assert_eq!(format_ms_with_offset(1_735_689_600_000, 0), "2025-01-01 00:00:00");
    }
}
