//! 本地时区偏移。
//!
//! 日志与界面上的时间必须是**服务器本地时间**：运维排查时对照的是
//! `事件查看器` 与 `netstat` 的输出，用 UTC 会造成误判。
//! 这里只在启动时读取一次并缓存，跨 DST 切换的进程重启即刷新。

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::OnceLock;
use windows::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};

/// `GetTimeZoneInformation` 的 DST 返回值（Win32 文档定义的常量值）。
const TZ_ID_DAYLIGHT: u32 = 2;
const TZ_ID_INVALID: u32 = 0xFFFF_FFFF;

/// 缓存，避免每次格式化都进系统调用。
static CACHED: OnceLock<i32> = OnceLock::new();
/// 供运行期强制刷新（用户改时区后不必重启）。
static OVERRIDE: AtomicI32 = AtomicI32::new(i32::MIN);

/// 本地时区相对 UTC 的偏移分钟数（东八区为 +480）。
///
/// 取不到时回退到 `portguard_core::time::DEFAULT_UTC_OFFSET_MINUTES`，
/// 绝不 panic —— 一个时间戳的显示格式不该让抓包线程倒下。
pub fn utc_offset_minutes() -> i32 {
    let forced = OVERRIDE.load(Ordering::Relaxed);
    if forced != i32::MIN {
        return forced;
    }
    *CACHED.get_or_init(probe)
}

/// 重新探测并覆盖缓存（用户修改系统时区后调用）。
pub fn refresh() {
    OVERRIDE.store(probe(), Ordering::Relaxed);
}

/// 清除运行期覆盖，回到系统探测值。
pub fn clear_override() {
    OVERRIDE.store(i32::MIN, Ordering::Relaxed);
}

fn probe() -> i32 {
    unsafe {
        let mut tz = TIME_ZONE_INFORMATION::default();
        let id = GetTimeZoneInformation(&mut tz);
        if id == TZ_ID_INVALID {
            return portguard_core::time::DEFAULT_UTC_OFFSET_MINUTES;
        }

        // Win32 的 Bias 定义：UTC = 本地时间 + Bias（分钟）。
        // 因此本地相对 UTC 的偏移 = -(Bias + 生效的附加 Bias)。
        let mut bias = tz.Bias;
        if id == TZ_ID_DAYLIGHT {
            bias = bias.saturating_add(tz.DaylightBias);
        } else {
            bias = bias.saturating_add(tz.StandardBias);
        }

        let offset = bias.saturating_neg();
        // 真实时区偏移不会超过 ±14 小时；超范围说明探测结果不可信。
        if offset.abs() > 14 * 60 {
            return portguard_core::time::DEFAULT_UTC_OFFSET_MINUTES;
        }
        offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// 覆盖值是进程级全局状态，测试必须串行访问。
    static SERIAL: Mutex<()> = Mutex::new(());

    #[test]
    fn 偏移在真实时区范围内() {
        let off = probe();
        assert!(
            (-14 * 60..=14 * 60).contains(&off),
            "探测到的偏移 {} 分钟不合常理",
            off
        );
    }

    #[test]
    fn 缓存与探测值一致() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        clear_override();
        assert_eq!(utc_offset_minutes(), utc_offset_minutes());
    }

    #[test]
    fn 可临时覆盖并清除() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        clear_override();
        let original = utc_offset_minutes();

        OVERRIDE.store(123, Ordering::Relaxed);
        assert_eq!(utc_offset_minutes(), 123);

        clear_override();
        assert_eq!(utc_offset_minutes(), original);
    }
}
