//! 封停列表持久化。
//!
//! 替代原程序的二进制 `BanData.bin`，改为可读的 JSON，
//! 便于运维直接查看与人工修数据（规范 14）。
//!
//! 写入采用「临时文件 + 原子替换」：进程在写盘途中被强杀也不会留下半截文件。

use portguard_core::error::{AppError, Result};
use portguard_core::model::BanRecord;
use portguard_core::time::now_ms;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// 持久化文件结构。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BanStore {
    /// 文件结构版本。
    #[serde(default = "default_version")]
    pub version: u32,
    /// 最近一次写入时间（Unix 纪元毫秒）。
    #[serde(default)]
    pub saved_at_ms: u64,
    /// 封停记录。
    #[serde(default)]
    pub bans: Vec<BanRecord>,
}

fn default_version() -> u32 {
    1
}

impl BanStore {
    pub fn new(bans: Vec<BanRecord>) -> BanStore {
        BanStore {
            version: 1,
            saved_at_ms: now_ms(),
            bans,
        }
    }

    /// 从文件加载。
    ///
    /// - 文件不存在：返回空列表（首次运行，属正常情况）；
    /// - 文件损坏：返回错误，由调用方决定是否备份后重建，
    ///   绝不静默丢弃用户的封停列表。
    pub fn load(path: &Path) -> Result<BanStore> {
        if !path.exists() {
            return Ok(BanStore::default());
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| AppError::Storage(format!("读取 {} 失败：{}", path.display(), e)))?;
        if text.trim().is_empty() {
            return Ok(BanStore::default());
        }
        serde_json::from_str(&text).map_err(|e| {
            AppError::Storage(format!("解析 {} 失败：{}", path.display(), e))
        })
    }

    /// 原子写入。
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir).map_err(|e| {
                    AppError::Storage(format!("创建目录 {} 失败：{}", dir.display(), e))
                })?;
            }
        }
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| AppError::Storage(format!("序列化封停列表失败：{}", e)))?;

        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| {
            AppError::Storage(format!("写入临时文件 {} 失败：{}", tmp.display(), e))
        })?;
        // Windows 上 rename 覆盖已存在文件是允许的（MoveFileEx 语义）。
        std::fs::rename(&tmp, path).map_err(|e| {
            AppError::Storage(format!("替换 {} 失败：{}", path.display(), e))
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portguard_core::model::{BanReason, Protocol};

    fn sample() -> Vec<BanRecord> {
        vec![
            BanRecord {
                ip: "203.0.113.9".parse().unwrap(),
                protocol: Some(Protocol::Tcp),
                service_port: Some(3389),
                remote_port: Some(44444),
                attempt_count: 7,
                created_at_ms: 1_700_000_000_000,
                expires_at_ms: Some(1_700_003_600_000),
                permanent: false,
                reason: BanReason::TcpThreshold,
                rule_name: "PortGuard-Ban-203.0.113.9".to_string(),
            },
            BanRecord {
                ip: "198.51.100.1".parse().unwrap(),
                protocol: None,
                service_port: None,
                remote_port: None,
                attempt_count: 0,
                created_at_ms: 1_700_000_100_000,
                expires_at_ms: None,
                permanent: true,
                reason: BanReason::Manual,
                rule_name: "PortGuard-Ban-198.51.100.1".to_string(),
            },
        ]
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("pg_bans_{}_{}.json", name, std::process::id()))
    }

    #[test]
    fn 保存后加载结果一致() {
        let p = tmp("roundtrip");
        let _ = std::fs::remove_file(&p);
        let store = BanStore::new(sample());
        store.save(&p).unwrap();
        let back = BanStore::load(&p).unwrap();
        assert_eq!(back.bans.len(), 2);
        assert_eq!(back.bans[0].ip, sample()[0].ip);
        assert!(back.bans[1].permanent);
        assert_eq!(back.version, 1);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn 文件不存在返回空列表() {
        let p = tmp("missing");
        let _ = std::fs::remove_file(&p);
        let store = BanStore::load(&p).unwrap();
        assert!(store.bans.is_empty());
    }

    #[test]
    fn 空文件返回空列表() {
        let p = tmp("empty");
        std::fs::write(&p, "   ").unwrap();
        assert!(BanStore::load(&p).unwrap().bans.is_empty());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn 损坏文件报错而非静默丢弃() {
        let p = tmp("broken");
        std::fs::write(&p, "{ 这不是合法 JSON").unwrap();
        let r = BanStore::load(&p);
        assert!(r.is_err(), "损坏的封停文件必须报错，不能静默当作空列表");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn 保存后不残留临时文件() {
        let p = tmp("tmpfile");
        let _ = std::fs::remove_file(&p);
        BanStore::new(sample()).save(&p).unwrap();
        assert!(!p.with_extension("json.tmp").exists());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn 缺少可选字段也能解析() {
        // 兼容未来/过去的结构变化：只给必要字段
        let p = tmp("partial");
        std::fs::write(&p, r#"{"bans":[]}"#).unwrap();
        let s = BanStore::load(&p).unwrap();
        assert_eq!(s.version, 1);
        assert_eq!(s.saved_at_ms, 0);
        let _ = std::fs::remove_file(&p);
    }
}
