//! 单实例守卫。
//!
//! 为什么必须限制单实例：
//! - 两个进程同时写 `netsh` 防火墙规则会互相删除对方刚建的规则；
//! - 两个进程同时抓包会重复计数，导致误封；
//! - 两个进程争抢同一个面板端口，后者必然启动失败。
//!
//! 用命名互斥体实现：进程存活期间系统持有该对象，退出（含崩溃）即自动释放，
//! 不需要「锁文件 + 陈旧检测」这种容易出错的方案。

use crate::wide::to_wide;
use crate::winerr::win_err;
use portguard_core::error::Result;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
use windows::Win32::System::Threading::CreateMutexW;

/// 默认互斥体名。`Global\` 前缀使其跨会话唯一（控制台登录 + 远程桌面同时开）。
const DEFAULT_NAME: &str = r"Global\PortGuard-Singleton";
/// 无权限创建 Global 命名对象时的回退名（当前会话内唯一）。
const FALLBACK_NAME: &str = r"Local\PortGuard-Singleton";

/// 单实例守卫。持有它即代表本进程独占；`Drop` 时释放。
#[derive(Debug)]
pub struct SingleInstance {
    handle: HANDLE,
    /// 实际使用的名称（Global 或回退后的 Local）。
    name: &'static str,
}

impl SingleInstance {
    /// 尝试获取单实例所有权。
    ///
    /// - `Ok(Some(_))`：本进程是唯一实例；
    /// - `Ok(None)`：已有实例在运行，调用方应提示用户后退出；
    /// - `Err(_)`：连互斥体都创建不出来（极罕见），调用方应记录并决定是否继续。
    pub fn acquire() -> Result<Option<SingleInstance>> {
        match Self::try_name(DEFAULT_NAME) {
            // 名称被占用 → 已有实例
            Ok(Some(guard)) => return Ok(Some(guard)),
            Ok(None) => return Ok(None),
            // Global 命名空间创建失败（非管理员 / 权限受限）→ 回退到会话级
            Err(_) => {}
        }
        Self::try_name(FALLBACK_NAME)
    }

    /// 实际使用的互斥体名，便于日志排查。
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// 用指定名称尝试创建。
    fn try_name(name: &'static str) -> Result<Option<SingleInstance>> {
        let wname = to_wide(name);
        unsafe {
            let handle = CreateMutexW(None, false, PCWSTR(wname.as_ptr()))
                .map_err(|e| win_err("CreateMutexW", &e))?;

            // CreateMutexW 在「名称已存在」时同样返回有效句柄，
            // 必须靠 GetLastError 区分——这是 Win32 的既定语义。
            if GetLastError() == ERROR_ALREADY_EXISTS {
                let _ = CloseHandle(handle);
                return Ok(None);
            }

            Ok(Some(SingleInstance { handle, name }))
        }
    }
}

impl Drop for SingleInstance {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 首次获取成功() {
        // 测试进程内首次获取应当成功（名称随进程隔离，避免与正在运行的程序冲突）
        let guard = SingleInstance::try_name(r"Local\PortGuard-Test-First").unwrap();
        assert!(guard.is_some());
    }

    #[test]
    fn 第二次获取失败() {
        let first = SingleInstance::try_name(r"Local\PortGuard-Test-Second").unwrap();
        assert!(first.is_some(), "首次获取应当成功");
        let second = SingleInstance::try_name(r"Local\PortGuard-Test-Second").unwrap();
        assert!(second.is_none(), "已有实例时必须拒绝第二个");
    }

    #[test]
    fn 释放后可重新获取() {
        {
            let g = SingleInstance::try_name(r"Local\PortGuard-Test-Release").unwrap();
            assert!(g.is_some());
        }
        // 互斥体随句柄关闭而销毁，因此可以再次获取
        let again = SingleInstance::try_name(r"Local\PortGuard-Test-Release").unwrap();
        assert!(again.is_some());
    }

    #[test]
    fn 记录实际使用的名称() {
        let g = SingleInstance::try_name(r"Local\PortGuard-Test-Name")
            .unwrap()
            .unwrap();
        assert_eq!(g.name(), r"Local\PortGuard-Test-Name");
    }
}
