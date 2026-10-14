//! IP 规则解析与匹配。
//!
//! 必须支持原程序的三种写法（规范 5）：
//!
//! ```text
//! 192.168.1.10                 单 IP
//! 192.168.1.1-192.168.1.100    闭区间
//! 192.168.1.*                  末段通配
//! ```
//!
//! 另外顺带支持 CIDR（`192.168.1.0/24`）与多段通配（`192.168.*.*`）。
//!
//! 性能约束（规范 21）：比较阶段全部使用 `u32`，禁止逐包做字符串切割。

use crate::error::{AppError, Result};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// 单个连续 IP 区间（含两端）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpRange {
    /// 起始地址（大端序 u32，与 `Ipv4Addr` 的 `u32::from` 一致）。
    pub start: u32,
    /// 结束地址（含）。
    pub end: u32,
}

impl IpRange {
    pub fn new(start: u32, end: u32) -> Self {
        // 用户把区间写反时自动纠正，不报错——语义无歧义。
        if start <= end {
            IpRange { start, end }
        } else {
            IpRange {
                start: end,
                end: start,
            }
        }
    }

    /// 判断给定 IP 是否落在区间内。
    #[inline]
    pub fn contains(&self, ip: u32) -> bool {
        ip >= self.start && ip <= self.end
    }

    /// 解析单条规则字符串。
    ///
    /// 支持：`a.b.c.d` / `a.b.c.d-e.f.g.h` / `a.b.c.*` / `a.b.c.*` 的多段形式 / `a.b.c.d/nn`。
    pub fn parse(raw: &str) -> Result<IpRange> {
        let s = raw.trim();
        if s.is_empty() {
            return Err(AppError::InvalidIpRule("空规则".into()));
        }

        if let Some((addr, prefix)) = s.split_once('/') {
            return Self::parse_cidr(addr.trim(), prefix.trim());
        }

        if let Some((a, b)) = s.split_once('-') {
            let start = parse_ipv4(a.trim())?;
            let end = parse_ipv4(b.trim())?;
            return Ok(IpRange::new(u32::from(start), u32::from(end)));
        }

        if s.contains('*') {
            return Self::parse_wildcard(s);
        }

        let ip = parse_ipv4(s)?;
        let v = u32::from(ip);
        Ok(IpRange {
            start: v,
            end: v,
        })
    }

    /// 解析 `192.168.1.0/24`。
    fn parse_cidr(addr: &str, prefix: &str) -> Result<IpRange> {
        let ip = parse_ipv4(addr)?;
        let bits: u32 = prefix
            .parse()
            .map_err(|_| AppError::InvalidIpRule(format!("前缀长度非法：{}", prefix)))?;
        if bits > 32 {
            return Err(AppError::InvalidIpRule(format!(
                "前缀长度超出 0-32：{}",
                prefix
            )));
        }
        let base = u32::from(ip);
        // bits == 0 时掩码为 0，单独处理避免移位溢出。
        let mask: u32 = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
        let start = base & mask;
        let end = start | !mask;
        Ok(IpRange { start, end })
    }

    /// 解析通配写法：`*` 只能出现在尾部连续段，例如 `192.168.1.*`、`192.168.*.*`。
    ///
    /// 非尾部通配（如 `192.*.1.*`）会解析出非连续集合，无法用单个区间表达，直接判为非法。
    fn parse_wildcard(s: &str) -> Result<IpRange> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return Err(AppError::InvalidIpRule(format!(
                "通配规则必须是 4 段 IPv4：{}",
                s
            )));
        }
        let mut start: u32 = 0;
        let mut end: u32 = 0;
        let mut wildcard_started = false;

        for part in parts.iter() {
            let is_wild = *part == "*";
            if is_wild && !wildcard_started {
                wildcard_started = true;
            }
            if !is_wild && wildcard_started {
                return Err(AppError::InvalidIpRule(format!(
                    "通配符只能出现在末尾连续段：{}",
                    s
                )));
            }
            let (lo, hi) = if is_wild {
                (0u32, 255u32)
            } else {
                let v: u32 = part
                    .parse()
                    .map_err(|_| AppError::InvalidIpRule(format!("段值非法：{}", part)))?;
                if v > 255 {
                    return Err(AppError::InvalidIpRule(format!("段值超出 0-255：{}", part)));
                }
                (v, v)
            };
            start = (start << 8) | lo;
            end = (end << 8) | hi;
        }
        Ok(IpRange { start, end })
    }

    /// 归一化为标准展示字符串。区间退化时输出单 IP。
    pub fn to_display_string(&self) -> String {
        if self.start == self.end {
            return u32_to_ip(self.start).to_string();
        }
        format!(
            "{}-{}",
            u32_to_ip(self.start),
            u32_to_ip(self.end)
        )
    }
}

/// 一组 IP 区间，规则匹配入口。
#[derive(Clone, Debug, Default)]
pub struct IpSet {
    ranges: Vec<IpRange>,
}

impl IpSet {
    /// 从用户输入的字符串列表构造。任一条非法即整体失败，避免「静默丢规则」。
    pub fn from_rules<S: AsRef<str>>(rules: &[S]) -> Result<IpSet> {
        let mut ranges = Vec::with_capacity(rules.len());
        for r in rules {
            let t = r.as_ref().trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            ranges.push(IpRange::parse(t)?);
        }
        Ok(IpSet { ranges })
    }

    /// 判断 IP 是否命中。
    #[inline]
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let v = u32::from(ip);
        self.ranges.iter().any(|r| r.contains(v))
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    pub fn ranges(&self) -> &[IpRange] {
        &self.ranges
    }
}

/// 严格解析点分十进制 IPv4。拒绝 `1.2.3`、`1.2.3.4.5`、前导零以外的宽松写法由 std 决定。
pub fn parse_ipv4(s: &str) -> Result<Ipv4Addr> {
    s.parse::<Ipv4Addr>()
        .map_err(|_| AppError::InvalidIpRule(format!("非法 IPv4 地址：{}", s)))
}

/// `u32` 转回点分十进制。
pub fn u32_to_ip(v: u32) -> Ipv4Addr {
    Ipv4Addr::from(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().expect("测试用 IP 必须合法")
    }

    #[test]
    fn 单地址规则() {
        let r = IpRange::parse("192.168.1.10").unwrap();
        assert_eq!(r.start, r.end);
        assert!(r.contains(u32::from(ip("192.168.1.10"))));
        assert!(!r.contains(u32::from(ip("192.168.1.11"))));
    }

    #[test]
    fn 区间规则() {
        let r = IpRange::parse("192.168.1.1-192.168.1.100").unwrap();
        assert!(r.contains(u32::from(ip("192.168.1.1"))));
        assert!(r.contains(u32::from(ip("192.168.1.100"))));
        assert!(r.contains(u32::from(ip("192.168.1.50"))));
        assert!(!r.contains(u32::from(ip("192.168.1.101"))));
        assert!(!r.contains(u32::from(ip("192.168.2.1"))));
    }

    #[test]
    fn 区间写反时自动纠正() {
        let a = IpRange::parse("192.168.1.100-192.168.1.1").unwrap();
        let b = IpRange::parse("192.168.1.1-192.168.1.100").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn 末段通配() {
        let r = IpRange::parse("192.168.1.*").unwrap();
        assert!(r.contains(u32::from(ip("192.168.1.0"))));
        assert!(r.contains(u32::from(ip("192.168.1.255"))));
        assert!(!r.contains(u32::from(ip("192.168.2.0"))));
        // 末段通配等价于 /24
        assert_eq!(r, IpRange::parse("192.168.1.0/24").unwrap());
    }

    #[test]
    fn 多段通配() {
        let r = IpRange::parse("192.168.*.*").unwrap();
        assert!(r.contains(u32::from(ip("192.168.0.0"))));
        assert!(r.contains(u32::from(ip("192.168.255.255"))));
        assert!(!r.contains(u32::from(ip("192.169.0.0"))));
    }

    #[test]
    fn 非尾部通配判定非法() {
        assert!(IpRange::parse("192.*.1.*").is_err());
    }

    #[test]
    fn 无类域间路由解析() {
        assert_eq!(
            IpRange::parse("10.0.0.0/8").unwrap(),
            IpRange {
                start: u32::from(ip("10.0.0.0")),
                end: u32::from(ip("10.255.255.255"))
            }
        );
        assert_eq!(
            IpRange::parse("0.0.0.0/0").unwrap(),
            IpRange {
                start: 0,
                end: u32::MAX
            }
        );
        assert!(IpRange::parse("10.0.0.0/33").is_err());
    }

    #[test]
    fn 非法输入被拒绝() {
        assert!(IpRange::parse("").is_err());
        assert!(IpRange::parse("1.2.3").is_err());
        assert!(IpRange::parse("999.1.1.1").is_err());
        assert!(IpRange::parse("abc").is_err());
        assert!(IpRange::parse("192.168.1.256").is_err());
    }

    #[test]
    fn 规则集匹配与空规则过滤() {
        let set = IpSet::from_rules(&[
            "192.168.1.1".to_string(),
            "".to_string(),
            "# 注释行".to_string(),
            "10.0.0.0/8".to_string(),
        ])
        .unwrap();
        assert_eq!(set.len(), 2);
        assert!(set.contains(ip("192.168.1.1")));
        assert!(set.contains(ip("10.5.5.5")));
        assert!(!set.contains(ip("172.16.0.1")));
    }

    #[test]
    fn 规则集遇非法规则整体失败() {
        let r = IpSet::from_rules(&["192.168.1.1".to_string(), "bad".to_string()]);
        assert!(r.is_err());
    }

    #[test]
    fn 白名单优先级测试数据可复用() {
        // 规范 26.2：白名单命中必须永远放行，这里只验证匹配层正确性。
        let wl = IpSet::from_rules(&["192.168.1.*".to_string()]).unwrap();
        assert!(wl.contains(ip("192.168.1.77")));
    }
}
