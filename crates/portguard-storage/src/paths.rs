//! 运行期路径解析。
//!
//! 目录布局（相对于 exe 所在目录，保证绿色部署）：
//!
//! ```text
//! PortGuard.exe
//! config.toml
//! state/bans.json
//! logs/portguard.log
//! data/            （ip2region 等可选数据）
//! ```

use portguard_core::error::{AppError, Result};
use std::path::{Path, PathBuf};

/// 程序运行期使用的全部路径。
#[derive(Clone, Debug)]
pub struct AppPaths {
    /// 根目录（默认为 exe 所在目录）。
    root: PathBuf,
}

impl AppPaths {
    /// 按 exe 所在目录解析。
    ///
    /// 取不到 exe 路径时（例如被以异常方式加载）回退到当前工作目录，
    /// 绝不 panic。
    pub fn resolve() -> AppPaths {
        let root = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));
        AppPaths { root }
    }

    /// 指定根目录（测试与便携模式用）。
    pub fn with_root(root: impl Into<PathBuf>) -> AppPaths {
        AppPaths { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `config.toml`
    pub fn config_file(&self) -> PathBuf {
        self.root.join("config.toml")
    }

    /// `state/bans.json`
    pub fn bans_file(&self) -> PathBuf {
        self.root.join("state").join("bans.json")
    }

    /// `state/` 目录
    pub fn state_dir(&self) -> PathBuf {
        self.root.join("state")
    }

    /// `logs/portguard.log`
    pub fn log_file(&self) -> PathBuf {
        self.root.join("logs").join("portguard.log")
    }

    /// `logs/` 目录
    pub fn log_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    /// `data/` 目录（IP 地理位置库等）
    pub fn data_dir(&self) -> PathBuf {
        self.root.join("data")
    }

    /// 创建所有必需目录。
    pub fn ensure(&self) -> Result<()> {
        for dir in [self.state_dir(), self.log_dir(), self.data_dir()] {
            std::fs::create_dir_all(&dir).map_err(|e| {
                AppError::Storage(format!("创建目录 {} 失败：{}", dir.display(), e))
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 路径拼接正确() {
        let p = AppPaths::with_root("D:/PortGuard");
        assert!(p.config_file().ends_with("config.toml"));
        assert!(p.bans_file().ends_with("bans.json"));
        assert!(p.log_file().ends_with("portguard.log"));
        assert!(p.bans_file().to_string_lossy().contains("state"));
        assert!(p.log_file().to_string_lossy().contains("logs"));
    }

    #[test]
    fn 解析出的根目录非空() {
        let p = AppPaths::resolve();
        assert!(!p.root().as_os_str().is_empty());
    }

    #[test]
    fn 可创建目录结构() {
        let base = std::env::temp_dir().join("portguard_paths_test");
        let _ = std::fs::remove_dir_all(&base);
        let p = AppPaths::with_root(&base);
        p.ensure().unwrap();
        assert!(p.state_dir().is_dir());
        assert!(p.log_dir().is_dir());
        assert!(p.data_dir().is_dir());
        let _ = std::fs::remove_dir_all(&base);
    }
}
