//! Win32 错误转换。
//!
//! `AppError::WindowsApi` 只保留 API 名与错误码：错误码足以在微软文档中查到
//! 确切原因，且不会因为系统语言不同而产生五花八门的文案。

use portguard_core::error::AppError;
use windows::core::Error as WinError;

/// 把 `windows` crate 的错误转换为项目统一错误。
///
/// - `api` 传入人可读的 API 名（如 `"CreateMutexW"`），便于日志定位；
/// - `HRESULT` 以 `u32` 形式保留原始码，不做有损截断。
pub fn win_err(api: &'static str, e: &WinError) -> AppError {
    AppError::WindowsApi {
        api,
        code: e.code().0 as u32,
    }
}

/// 取系统最后一次错误码（`GetLastError` 路径使用）。
pub fn code_of(e: &WinError) -> u32 {
    e.code().0 as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::core::HRESULT;

    #[test]
    fn 错误码被完整保留() {
        // 0x80070005 即拒绝访问，常用于权限不足
        let e = WinError::from_hresult(HRESULT(0x8007_0005u32 as i32));
        let err = win_err("OpenProcessToken", &e);
        match err {
            AppError::WindowsApi { api, code } => {
                assert_eq!(api, "OpenProcessToken");
                assert_eq!(code, 0x8007_0005);
            }
            other => panic!("错误类型不符：{:?}", other),
        }
    }

    #[test]
    fn 高位错误码不丢符号位() {
        let e = WinError::from_hresult(HRESULT(-1));
        assert_eq!(code_of(&e), u32::MAX);
    }
}
