//! IP 地理位置查询（ip2region xdb）。
//!
//! **定位（规范 22）：地理位置只用于展示，绝不参与封停判定。**
//! 因此本 crate 不依赖任何 Windows API，查询失败一律返回「未知」，
//! 调用方不得因为查不到地理位置而改变判定顺序或封停行为。
//!
//! 查询开销是「向量索引定位 + 段索引二分」，文件整体驻留内存，
//! 面板每秒刷新时直接调用即可，无需额外缓存。
//!
//! ```text
//! GeoLookup::load(配置开关, 候选路径)
//!     ├─ 关闭      → describe() 恒为「未知」
//!     ├─ 加载成功   → status() 给出所用文件路径
//!     └─ 缺失/损坏  → status() 给出中文原因，describe() 恒为「未知」
//! ```

// 非测试代码禁止 unwrap/expect（规范 26：失败必须显式处理）。
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod db;
mod record;

pub use db::GeoDb;
pub use record::GeoRecord;

use std::net::Ipv4Addr;
use std::path::PathBuf;

/// 查询不到地理位置时的展示文案（规范 22）。
pub const UNKNOWN: &str = "未知";

/// 地理位置库的运行期状态与查询入口。
///
/// 把「是否启用、文件在哪、能不能用」收敛成一个对象，
/// 让调用方只需回答「这个 IP 该显示什么」。
pub struct GeoLookup {
    db: Option<GeoDb>,
    /// 供日志与面板展示的中文状态说明。
    status: String,
}

impl GeoLookup {
    /// 按候选路径依次尝试加载。
    ///
    /// `enabled` 为 `false` 时不做任何文件访问；候选路径全部不存在时
    /// 保留一条说明了「该把文件放哪」的状态，而不是静默降级。
    pub fn load(enabled: bool, candidates: &[PathBuf]) -> GeoLookup {
        if !enabled {
            return GeoLookup {
                db: None,
                status: "地理位置展示已在配置中关闭".to_string(),
            };
        }
        let mut tried: Vec<String> = Vec::with_capacity(candidates.len());
        for path in candidates {
            if !path.is_file() {
                tried.push(path.display().to_string());
                continue;
            }
            return match GeoDb::open(path) {
                Ok(db) => GeoLookup {
                    db: Some(db),
                    status: path.display().to_string(),
                },
                Err(e) => GeoLookup {
                    db: None,
                    status: format!("加载失败：{}", e),
                },
            };
        }
        GeoLookup {
            db: None,
            status: format!("未找到地理位置库，请放入 {}", tried.join(" 或 ")),
        }
    }

    /// 数据库是否已可用。
    pub fn ready(&self) -> bool {
        self.db.is_some()
    }

    /// 状态说明（加载成功时为数据库路径，否则为原因）。
    pub fn status(&self) -> &str {
        &self.status
    }

    /// 生成某个 IP 的展示文本；未加载、未命中、格式非法一律返回「未知」。
    pub fn describe(&self, ip: &str) -> String {
        let addr: Ipv4Addr = match ip.trim().parse() {
            Ok(a) => a,
            Err(_) => return UNKNOWN.to_string(),
        };
        match &self.db {
            Some(db) => match db.lookup(u32::from(addr)) {
                Some(record) => record.describe(),
                None => UNKNOWN.to_string(),
            },
            None => UNKNOWN.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 关闭时不做文件访问且恒为未知() {
        let lookup = GeoLookup::load(false, &[PathBuf::from("不存在的路径.xdb")]);
        assert!(!lookup.ready());
        assert!(lookup.status().contains("关闭"));
        assert_eq!(lookup.describe("8.8.8.8"), UNKNOWN);
    }

    #[test]
    fn 找不到文件时状态指明应放位置() {
        let missing = PathBuf::from("data").join("ip2region_v4.xdb");
        let lookup = GeoLookup::load(true, &[missing.clone()]);
        assert!(!lookup.ready());
        assert!(lookup.status().contains("ip2region_v4.xdb"));
        assert_eq!(lookup.describe("8.8.8.8"), UNKNOWN);
    }

    #[test]
    fn 非法地址不会被当成查询失败以外的事() {
        let lookup = GeoLookup::load(false, &[]);
        assert_eq!(lookup.describe("不是IP"), UNKNOWN);
        assert_eq!(lookup.describe(""), UNKNOWN);
    }

    #[test]
    fn 候选路径中命中第一个存在的文件() {
        let dir = std::env::temp_dir().join(format!("pg_geo_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let missing = dir.join("没有这个文件.xdb");
        // 用本 crate 的源码文件冒充一个「存在但不是数据库」的文件，
        // 验证加载失败时状态里带上了失败原因，而不是被当成未找到。
        let bogus = dir.join("坏的.xdb");
        std::fs::write(&bogus, b"not a database").expect("写入临时文件失败");

        let lookup = GeoLookup::load(true, &[missing, bogus]);
        assert!(!lookup.ready());
        assert!(lookup.status().contains("加载失败"), "状态：{}", lookup.status());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn 真实数据库可查询常见地址() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ip2region_v4.xdb");
        if !path.is_file() {
            return;
        }
        let lookup = GeoLookup::load(true, &[path]);
        assert!(lookup.ready(), "状态：{}", lookup.status());
        // 114.114.114.114 的记录是「中国|江苏省|南京市|0|CN」，ISP 为占位 0 应被跳过
        assert_eq!(lookup.describe("114.114.114.114"), "中国 · 江苏省 · 南京市");
        assert_eq!(lookup.describe("192.168.1.1"), "保留地址");
        assert!(lookup.describe("8.8.8.8").contains("United States"));
        // 保留地址段不应被当成「未知」
        assert_ne!(lookup.describe("10.0.0.1"), UNKNOWN);
    }
}
