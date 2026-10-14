//! ip2region xdb 文件格式解析与查询。
//!
//! 文件布局（IPv4 数据库，已按真实 `ip2region_v4.xdb` 实测确认）：
//!
//! ```text
//! [0, 256)              头部
//!   [0,2)   版本号（3）
//!   [2,4)   索引策略（1 = 向量索引）
//!   [4,8)   生成时间戳（Unix 秒）
//!   [8,12)  段索引区起始（绝对文件偏移）
//!   [12,16) 段索引区末块起始
//!   [16,18) IP 版本（4）
//!   [18,20) 指针字节数（4）
//! [256, 524544)         向量索引：256 × 256 项，每项 8 字节
//!                        (段索引起始偏移, 段索引结束偏移)
//! [524544, 段索引起始)   地域信息数据区：UTF-8 文本，记录首尾相接无分隔符
//! [段索引起始, 文件尾)   段索引：每块 14 字节
//!                        start_ip(4) end_ip(4) data_len(2) data_ptr(4)
//! ```
//!
//! 查询流程：取 IP 的前两个字节定位向量索引项 → 得到该 IP 段落在段索引中的
//! 半开区间 → 在区间内二分 → 命中块的 `data_ptr` 指向数据区中的**绝对文件偏移**，
//! 按 `data_len` 截取即为记录文本。
//!
//! 文件整体一次性读入内存（约 10 MB）。相比每次查询 `seek` + `read`，
//! 内存副本让查询只做内存比较，且无需处理文件被并发改写的问题。

use std::path::Path;

use portguard_core::error::{AppError, Result};

use crate::record::GeoRecord;

/// 头部长度。
const HEADER_LEN: usize = 256;
/// 向量索引行数与列数。
const VECTOR_ROWS: usize = 256;
const VECTOR_COLS: usize = 256;
/// 向量索引单项长度。
const VECTOR_ENTRY_LEN: usize = 8;
/// 向量索引区总长度（256 × 256 × 8 = 512 KiB）。
const VECTOR_LEN: usize = VECTOR_ROWS * VECTOR_COLS * VECTOR_ENTRY_LEN;
/// 段索引块长度。
const SEGMENT_LEN: usize = 14;
/// 文件最小长度：头部 + 向量索引 + 一个段索引块。
const MIN_LEN: usize = HEADER_LEN + VECTOR_LEN + SEGMENT_LEN;

/// 支持的数据库版本号。
const SUPPORTED_VERSION: u16 = 3;
/// 支持的索引策略：向量索引。
const VECTOR_INDEX_POLICY: u16 = 1;
/// 支持的 IP 版本：IPv4。
const IP_VERSION_V4: u16 = 4;
/// 支持的指针字节数。
const PTR_LEN: u32 = 4;

/// 已加载的 ip2region 数据库。
#[derive(Debug)]
pub struct GeoDb {
    bytes: Vec<u8>,
}

impl GeoDb {
    /// 从文件加载；格式不符时返回中文错误，不 panic。
    pub fn open(path: &Path) -> Result<GeoDb> {
        let bytes = std::fs::read(path)
            .map_err(|e| AppError::Storage(format!("读取 {} 失败：{}", path.display(), e)))?;
        GeoDb::from_bytes(bytes).map_err(|e| {
            AppError::Storage(format!("{} 不是可用的 ip2region 库：{}", path.display(), e))
        })
    }

    /// 从字节加载并校验头部。
    pub fn from_bytes(bytes: Vec<u8>) -> Result<GeoDb> {
        let db = GeoDb { bytes };
        db.check_header()?;
        Ok(db)
    }

    /// 数据文件字节数。
    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    /// 查询 IPv4 地址；未命中返回 `None`。
    ///
    /// 任何越界、截断、非法编码都只会得到 `None`，绝不 panic——
    /// 地理位置只用于展示，不能因为一个坏文件把面板打挂。
    pub fn lookup(&self, ip: u32) -> Option<GeoRecord> {
        let row = (ip >> 24) as usize;
        let col = ((ip >> 16) & 0xFF) as usize;
        let entry = HEADER_LEN + (row * VECTOR_COLS + col) * VECTOR_ENTRY_LEN;
        let first = self.u32_at(entry)? as usize;
        let second = self.u32_at(entry + 4)? as usize;
        // 两个端点谁大谁小不影响语义，统一成半开区间 [lo, hi)
        let (lo, hi) = if first <= second {
            (first, second)
        } else {
            (second, first)
        };
        if lo < HEADER_LEN || hi > self.bytes.len() {
            return None;
        }

        let mut left = 0usize;
        let mut right = (hi - lo) / SEGMENT_LEN;
        while left < right {
            let mid = left + (right - left) / 2;
            let offset = lo + mid * SEGMENT_LEN;
            let start = self.u32_at(offset)?;
            let end = self.u32_at(offset + 4)?;
            if ip < start {
                right = mid;
            } else if ip > end {
                left = mid + 1;
            } else {
                return self.record_at(offset);
            }
        }
        None
    }

    /// 读取一个段索引块指向的记录。
    fn record_at(&self, block_offset: usize) -> Option<GeoRecord> {
        let len = self.u16_at(block_offset + 8)? as usize;
        let ptr = self.u32_at(block_offset + 10)? as usize;
        let raw = self.bytes.get(ptr..ptr.checked_add(len)?)?;
        // 记录是 UTF-8 文本；非法编码说明文件损坏，按未知处理
        let text = std::str::from_utf8(raw).ok()?;
        Some(GeoRecord::parse(text))
    }

    /// 校验头部：版本、索引策略、IP 版本、指针宽度与段索引区范围。
    fn check_header(&self) -> Result<()> {
        if self.bytes.len() < MIN_LEN {
            return Err(AppError::Other(format!(
                "文件仅 {} 字节，不足以容纳 256 字节头部与 512 KiB 向量索引",
                self.bytes.len()
            )));
        }
        // 以下读取在长度校验之后，越界不可能发生
        let version = self.u16_at(0).unwrap_or(0);
        if version != SUPPORTED_VERSION {
            return Err(AppError::Other(format!(
                "数据库版本为 {}，本程序只支持 {}",
                version, SUPPORTED_VERSION
            )));
        }
        let policy = self.u16_at(2).unwrap_or(0);
        if policy != VECTOR_INDEX_POLICY {
            return Err(AppError::Other(format!(
                "索引策略为 {}，本程序只支持向量索引（{}）",
                policy, VECTOR_INDEX_POLICY
            )));
        }
        let ip_version = self.u16_at(16).unwrap_or(0);
        if ip_version != IP_VERSION_V4 {
            return Err(AppError::Other(format!(
                "这是 IPv{} 数据库，请使用 ip2region_v4.xdb",
                ip_version
            )));
        }
        let ptr_len = self.u16_at(18).unwrap_or(0) as u32;
        if ptr_len != PTR_LEN {
            return Err(AppError::Other(format!(
                "指针宽度为 {} 字节，本程序只支持 {}",
                ptr_len, PTR_LEN
            )));
        }
        let index_start = self.u32_at(8).unwrap_or(0) as usize;
        if index_start < HEADER_LEN + VECTOR_LEN
            || index_start.checked_add(SEGMENT_LEN).is_none()
            || index_start + SEGMENT_LEN > self.bytes.len()
        {
            return Err(AppError::Other(format!(
                "段索引区偏移 {} 越界（文件 {} 字节）",
                index_start,
                self.bytes.len()
            )));
        }
        Ok(())
    }

    fn u16_at(&self, offset: usize) -> Option<u16> {
        let raw: [u8; 2] = self
            .bytes
            .get(offset..offset.checked_add(2)?)?
            .try_into()
            .ok()?;
        Some(u16::from_le_bytes(raw))
    }

    fn u32_at(&self, offset: usize) -> Option<u32> {
        let raw: [u8; 4] = self
            .bytes
            .get(offset..offset.checked_add(4)?)?
            .try_into()
            .ok()?;
        Some(u32::from_le_bytes(raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// 数据区起始 = 头部 + 向量索引，与真实文件一致。
    const DATA_BASE: usize = HEADER_LEN + VECTOR_LEN;

    /// 构造一个最小可用的 xdb：`(起始 IP, 结束 IP, 记录文本)`。
    ///
    /// 记录按顺序写入数据区，段索引紧随其后，向量索引按 `IP >> 16` 落位。
    fn build_db(entries: &[(u32, u32, &str)]) -> Vec<u8> {
        let mut data = Vec::new();
        let mut pointers = Vec::new();
        for (_start, _end, text) in entries {
            pointers.push((DATA_BASE + data.len(), text.len()));
            data.extend_from_slice(text.as_bytes());
        }
        let segment_base = DATA_BASE + data.len();

        let mut out = vec![0u8; DATA_BASE];
        out[0..2].copy_from_slice(&SUPPORTED_VERSION.to_le_bytes());
        out[2..4].copy_from_slice(&VECTOR_INDEX_POLICY.to_le_bytes());
        out[8..12].copy_from_slice(&(segment_base as u32).to_le_bytes());
        out[16..18].copy_from_slice(&IP_VERSION_V4.to_le_bytes());
        out[18..20].copy_from_slice(&(PTR_LEN as u16).to_le_bytes());
        out.extend_from_slice(&data);

        for (i, (start, end, _text)) in entries.iter().enumerate() {
            let mut block = [0u8; SEGMENT_LEN];
            block[0..4].copy_from_slice(&start.to_le_bytes());
            block[4..8].copy_from_slice(&end.to_le_bytes());
            block[8..10].copy_from_slice(&(pointers[i].1 as u16).to_le_bytes());
            block[10..14].copy_from_slice(&(pointers[i].0 as u32).to_le_bytes());
            out.extend_from_slice(&block);
        }

        for (i, (start, _end, _text)) in entries.iter().enumerate() {
            let row = (*start >> 24) as usize;
            let col = ((*start >> 16) & 0xFF) as usize;
            let entry = HEADER_LEN + (row * VECTOR_COLS + col) * VECTOR_ENTRY_LEN;
            let block_start = (segment_base + i * SEGMENT_LEN) as u32;
            out[entry..entry + 4].copy_from_slice(&block_start.to_le_bytes());
            out[entry + 4..entry + 8].copy_from_slice(&(block_start + SEGMENT_LEN as u32).to_le_bytes());
        }
        out
    }

    fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from(Ipv4Addr::new(a, b, c, d))
    }

    fn sample() -> GeoDb {
        let bytes = build_db(&[
            (ip(0, 0, 0, 0), ip(0, 255, 255, 255), "Reserved|Reserved|Reserved|0|0"),
            (ip(8, 8, 0, 0), ip(8, 8, 255, 255), "United States|California|0|Google LLC|US"),
            (ip(114, 114, 0, 0), ip(114, 114, 255, 255), "中国|福建省|福州市|中国电信|CN"),
        ]);
        GeoDb::from_bytes(bytes).expect("构造的数据库应当合法")
    }

    #[test]
    fn 命中的地址返回对应记录() {
        let db = sample();
        let record = db.lookup(ip(114, 114, 114, 114)).expect("114.114.114.114 应命中");
        assert_eq!(record.country, "中国");
        assert_eq!(record.describe(), "中国 · 福建省 · 福州市 · 中国电信");

        let record = db.lookup(ip(8, 8, 8, 8)).expect("8.8.8.8 应命中");
        assert!(record.describe().contains("Google LLC"));
    }

    #[test]
    fn 未命中的地址返回空() {
        let db = sample();
        assert!(db.lookup(ip(1, 1, 1, 1)).is_none());
    }

    #[test]
    fn 保留地址段被识别() {
        let db = sample();
        let record = db.lookup(ip(0, 0, 0, 1)).expect("0.0.0.1 应命中保留段");
        assert!(record.is_reserved());
        assert_eq!(record.describe(), "保留地址");
    }

    #[test]
    fn 版本不符被拒绝() {
        let mut bytes = build_db(&[(ip(1, 0, 0, 0), ip(1, 0, 0, 255), "x|0|0|0|CN")]);
        bytes[0..2].copy_from_slice(&9u16.to_le_bytes());
        assert!(GeoDb::from_bytes(bytes).is_err());
    }

    #[test]
    fn ipv6数据库被拒绝() {
        let mut bytes = build_db(&[(ip(1, 0, 0, 0), ip(1, 0, 0, 255), "x|0|0|0|CN")]);
        bytes[16..18].copy_from_slice(&6u16.to_le_bytes());
        let err = GeoDb::from_bytes(bytes).unwrap_err().to_string();
        assert!(err.contains("ip2region_v4.xdb"), "错误应指明需要哪个文件：{}", err);
    }

    #[test]
    fn 文件被截断时加载失败() {
        let bytes = build_db(&[(ip(1, 0, 0, 0), ip(1, 0, 0, 255), "x|0|0|0|CN")]);
        let truncated = bytes[..MIN_LEN - 1].to_vec();
        assert!(GeoDb::from_bytes(truncated).is_err());
    }

    #[test]
    fn 记录指针越界只返回空不恐慌() {
        const TEXT: &str = "x|0|0|0|CN";
        let mut bytes = build_db(&[(ip(1, 0, 0, 0), ip(1, 0, 0, 255), TEXT)]);
        let segment_base = DATA_BASE + TEXT.len();
        // 把数据指针改到文件之外
        bytes[segment_base + 10..segment_base + 14]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        let db = GeoDb::from_bytes(bytes).expect("头部仍然合法");
        assert!(db.lookup(ip(1, 0, 0, 1)).is_none());
    }

    #[test]
    fn 真实数据库可加载并命中已知地址() {
        // 数据库不随源码分发，缺失时跳过（不影响 CI）
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ip2region_v4.xdb");
        if !path.is_file() {
            return;
        }
        let db = GeoDb::open(&path).expect("真实数据库应能加载");
        assert!(db.byte_len() > 1024 * 1024);

        let google = db.lookup(ip(8, 8, 8, 8)).expect("8.8.8.8 应有记录");
        assert!(
            google.country.contains("United States"),
            "8.8.8.8 应落在美国：{:?}",
            google
        );

        let chinanet = db.lookup(ip(114, 114, 114, 114)).expect("114.114.114.114 应有记录");
        assert_eq!(chinanet.country, "中国");

        // 内网与保留地址段必须落在 Reserved 记录上
        assert!(db.lookup(ip(192, 168, 1, 1)).expect("内网地址应有记录").is_reserved());
        assert!(db.lookup(ip(255, 255, 255, 255)).expect("广播地址应有记录").is_reserved());
    }
}
