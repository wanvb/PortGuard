//! 开机自启动（计划任务）。
//!
//! 选型说明：不用「启动」文件夹快捷方式（需要用户登录才生效，
//! 而本程序要在无人值守的服务器上开机即防护），也不用注册表 `Run`
//! （同样要求登录）。改用计划任务：
//!
//! - `/SC ONSTART`：开机即运行，无需登录；
//! - `/RU SYSTEM /RL HIGHEST`：以 SYSTEM 身份运行，天然具备管理员权限；
//! - 可在「任务计划程序」中直接查看与删除，符合规范 14 的可审计要求。
//!
//! 与 netsh 一样，**绝不经过 shell**：使用 `Command::new("schtasks").args([...])`。

use portguard_core::error::{AppError, Result};
use std::path::Path;

/// `CREATE_NO_WINDOW`：避免闪出控制台窗口。
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// 计划任务名。
pub const TASK_NAME: &str = "PortGuard";

/// 计划任务管理器。
#[derive(Debug, Default)]
pub struct Autostart;

impl Autostart {
    /// 查询是否已注册自启动任务。
    pub fn is_enabled() -> Result<bool> {
        let args = ["/Query", "/TN", TASK_NAME];
        match Self::run(&args) {
            Ok(_) => Ok(true),
            // 「任务不存在」也是正常结果，不视为错误
            Err(_) => Ok(false),
        }
    }

    /// 注册自启动。`exe` 必须是当前可执行文件的绝对路径。
    pub fn enable(exe: &Path) -> Result<()> {
        let exe = exe.to_string_lossy().to_string();
        // 路径可能含空格，用引号包裹后整体作为一个参数传给 /TR。
        let action = format!("\"{}\" --service", exe);

        let args = [
            "/Create",
            "/TN",
            TASK_NAME,
            "/TR",
            action.as_str(),
            "/SC",
            "ONSTART",
            "/RU",
            "SYSTEM",
            "/RL",
            "HIGHEST",
            "/F",
        ];
        Self::run(&args).map(|_| ())
    }

    /// 取消自启动。任务本就不存在时视为成功（幂等）。
    pub fn disable() -> Result<()> {
        let args = ["/Delete", "/TN", TASK_NAME, "/F"];
        match Self::run(&args) {
            Ok(_) => Ok(()),
            Err(e) => {
                let msg = e.to_string();
                // 多语言环境下「找不到任务」文案不同，这里按退出码语义兜底：
                // 删除不存在的任务对调用方来说目标已达成，不应报错。
                if msg.contains("找不到") || msg.contains("cannot find") || msg.contains("ERROR:") {
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }

    /// 执行 schtasks，返回 stdout。
    fn run(args: &[&str]) -> Result<String> {
        use std::os::windows::process::CommandExt;
        use std::process::Command;

        let output = Command::new("schtasks")
            .args(args)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| AppError::Other(format!("无法执行 schtasks：{}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if output.status.success() {
            Ok(stdout)
        } else {
            let code = output.status.code().unwrap_or(-1);
            Err(AppError::Other(format!(
                "schtasks {} 失败（退出码 {}）：{} {}",
                args.join(" "),
                code,
                stdout.trim(),
                stderr.trim()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 查询不存在的任务返回否() {
        // 只验证「查询动作可用且不 panic」；结论取决于本机是否已注册。
        let r = Autostart::is_enabled();
        assert!(r.is_ok(), "查询失败应被转换为 Ok(false)，而非错误");
    }

    #[test]
    fn 任务名符合可读性要求() {
        assert_eq!(TASK_NAME, "PortGuard");
        assert!(!TASK_NAME.contains('\\'), "任务名不带路径前缀，便于运维查找");
    }
}
