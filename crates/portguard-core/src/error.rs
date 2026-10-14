//! 统一错误类型。
//!
//! 规范要求：网络线程、防火墙、Win32 API、文件 I/O、配置加载路径上一律禁止
//! `unwrap()` / `expect()`，全部通过本模块的 `Result` 向上传播。

use thiserror::Error;

/// 全项目统一错误类型。
#[derive(Debug, Error)]
pub enum AppError {
    /// Win32 / WinSock API 调用失败，保留 API 名与错误码便于排查。
    #[error("Windows API 调用失败：{api}（错误码 {code}）")]
    WindowsApi { api: &'static str, code: u32 },

    /// 套接字相关错误。
    #[error("套接字错误：{0}")]
    Socket(String),

    /// 防火墙操作错误。
    #[error("防火墙操作失败：{0}")]
    Firewall(String),

    /// 配置读写或校验错误。
    #[error("配置错误：{0}")]
    Config(String),

    /// 持久化 / 文件读写错误。
    #[error("存储错误：{0}")]
    Storage(String),

    /// 数据包解析错误。
    #[error("数据包解析失败：{0}")]
    PacketParse(String),

    /// 权限不足：必须管理员身份运行。
    #[error("权限不足：请以管理员身份运行 PortGuard")]
    PermissionDenied,

    /// 内置 Web 服务错误。
    #[error("Web 服务错误：{0}")]
    Web(String),

    /// IP 规则字符串格式非法。
    #[error("IP 规则格式非法：{0}")]
    InvalidIpRule(String),

    /// 域名 / 适配器等其他业务错误。
    #[error("{0}")]
    Other(String),
}

/// 项目统一 Result 别名。
pub type Result<T> = std::result::Result<T, AppError>;

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Storage(e.to_string())
    }
}

impl From<toml::de::Error> for AppError {
    fn from(e: toml::de::Error) -> Self {
        AppError::Config(e.to_string())
    }
}

impl From<toml::ser::Error> for AppError {
    fn from(e: toml::ser::Error) -> Self {
        AppError::Config(e.to_string())
    }
}
