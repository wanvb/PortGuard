//! 管理员权限检查。
//!
//! 为什么必须检查：抓包需要 `SIO_RCVALL`，写防火墙规则需要修改
//! `netsh advfirewall`，两者都要求提升后的令牌。非管理员运行时
//! 这些操作会失败，程序必须**在启动时**如实告知用户，
//! 而不是等到第一次封停失败才暴露（规范 26.1）。

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// 当前进程是否以管理员（提升）权限运行。
///
/// 使用 `TokenElevation`：它反映的是**当前实际生效**的权限，
/// 而 `TokenElevationType` 只描述 UAC 类型，在「以管理员身份运行但
/// UAC 已关闭」的老系统上会给出错误结论。
pub fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut TOKEN_ELEVATION as *mut core::ffi::c_void),
            core::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
        .is_ok();

        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

/// 供启动日志使用的中文诊断文本。
///
/// 本程序不自带 UAC 清单（需兼容 Win7，且常以计划任务 / 服务方式启动），
/// 因此权限不足只能在启动时提示，而不能依赖系统弹窗。
pub fn describe() -> &'static str {
    if is_elevated() {
        "管理员权限：已获得"
    } else {
        "管理员权限：缺失（抓包与防火墙操作将失败，请以管理员身份重新运行）"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 权限检查不崩溃且结论自洽() {
        // 只要求调用安全，结论取决于测试运行环境。
        let e = is_elevated();
        let text = describe();
        assert_eq!(text.contains("已获得"), e);
    }
}
