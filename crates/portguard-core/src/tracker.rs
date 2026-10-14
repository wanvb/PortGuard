//! 连接行为跟踪器。
//!
//! 职责：按「对端 IP + 本机服务端口 + 保护分组」累计连接事件次数。
//!
//! 设计要点：
//! - 计数为**累计值**，不做滑动窗口：只要该来源还在活动，次数就一直累加，
//!   达到阈值即封停（规范 5.1）。滑出窗口就归零会让「间隔几十秒反复连接」
//!   永远够不到阈值，这正是要避免的漏封。
//! - 归零只有一条路径：该条目连续空闲超过保留期后被 `prune` 回收，
//!   下次再出现时重新从 0 开始。因此「打完就走的扫描」会迅速累计，
//!   而「隔天来一次的正常访问」不会跨天叠加。
//! - 时间由调用方注入（`now_ms`），因此完全可单元测试，不依赖真实时钟。
//! - 提供上限保护与显式 `prune`，防止长期运行时条目无限增长（规范 33 稳定性要求）。

use crate::model::PortGroup;
use std::collections::HashMap;

/// 跟踪键：一个「对端 IP → 本机某端口」的访问关系。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TrackKey {
    /// 对端 IP（大端序 u32）。
    pub ip: u32,
    /// 本机服务端口。
    pub port: u16,
    /// 保护分组（决定使用哪一套阈值）。
    pub group: PortGroup,
}

/// 单个键的统计状态。
#[derive(Clone, Debug)]
pub struct TrackEntry {
    /// 累计连接次数（条目的生命周期内只增不减）。
    pub count: u32,
    /// 首次出现时间。
    pub first_seen_ms: u64,
    /// 最近一次出现时间。
    pub last_seen_ms: u64,
}

impl TrackEntry {
    fn new(now_ms: u64) -> Self {
        TrackEntry {
            count: 0,
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
        }
    }
}

/// 跟踪器。
#[derive(Debug)]
pub struct ConnectionTracker {
    entries: HashMap<TrackKey, TrackEntry>,
    /// 条目数硬上限，超出时淘汰最久未活跃的条目，避免恶意源撑爆内存。
    max_entries: usize,
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        ConnectionTracker::new()
    }
}

impl ConnectionTracker {
    /// 默认上限 65536 条目（约数 MB 内存量级）。
    pub fn new() -> Self {
        ConnectionTracker {
            entries: HashMap::new(),
            max_entries: 65_536,
        }
    }

    /// 指定上限构造（测试用）。
    pub fn with_max_entries(max_entries: usize) -> Self {
        ConnectionTracker {
            entries: HashMap::new(),
            max_entries: max_entries.max(1),
        }
    }

    /// 记录一次事件，返回该键的累计事件次数。
    pub fn record(&mut self, key: TrackKey, now_ms: u64) -> u32 {
        if self.entries.len() >= self.max_entries && !self.entries.contains_key(&key) {
            self.evict_least_recent();
        }
        let entry = self
            .entries
            .entry(key)
            .or_insert_with(|| TrackEntry::new(now_ms));
        entry.last_seen_ms = now_ms;
        entry.count = entry.count.saturating_add(1);
        entry.count
    }

    /// 全量清理：移除最后活跃时间早于 `retention_ms` 的条目。
    ///
    /// 返回被清理的条目数。应由后台定时任务周期性调用。
    /// 被清理的条目连同其累计次数一起消失，该来源下次出现时从 0 重新计数。
    pub fn prune(&mut self, now_ms: u64, retention_ms: u64) -> usize {
        let cutoff = now_ms.saturating_sub(retention_ms);
        let before = self.entries.len();
        self.entries.retain(|_, e| e.last_seen_ms >= cutoff);
        before - self.entries.len()
    }

    /// 淘汰最久未活跃的条目。
    fn evict_least_recent(&mut self) {
        let victim = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.last_seen_ms)
            .map(|(k, _)| *k);
        if let Some(k) = victim {
            self.entries.remove(&k);
        }
    }

    /// 遍历所有条目（供 Web 面板构造「当前连接」视图）。
    pub fn iter_entries(&self) -> impl Iterator<Item = (&TrackKey, &TrackEntry)> {
        self.entries.iter()
    }

    /// 当前条目数。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 删除某个 IP 的全部跟踪记录（解封或加入白名单后调用）。
    pub fn remove_ip(&mut self, ip: u32) -> usize {
        let before = self.entries.len();
        self.entries.retain(|k, _| k.ip != ip);
        before - self.entries.len()
    }

    /// 清空所有跟踪状态（停止监听时调用）。
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(ip: &str, port: u16, group: PortGroup) -> TrackKey {
        TrackKey {
            ip: u32::from(ip.parse::<std::net::Ipv4Addr>().unwrap()),
            port,
            group,
        }
    }

    #[test]
    fn 累计计数逐次递增() {
        let mut t = ConnectionTracker::new();
        let k = key("1.2.3.4", 3389, PortGroup::Tcp);
        assert_eq!(t.record(k, 1_000), 1);
        assert_eq!(t.record(k, 2_000), 2);
        assert_eq!(t.record(k, 3_000), 3);
    }

    #[test]
    fn 间隔很久也继续累计() {
        // 滑动窗口判定会在这里归零，导致反复但稀疏的连接永远封不掉。
        let mut t = ConnectionTracker::new();
        let k = key("1.2.3.4", 3389, PortGroup::Tcp);
        assert_eq!(t.record(k, 1_000), 1);
        assert_eq!(t.record(k, 600_000), 2);
        assert_eq!(t.record(k, 1_200_000), 3);
    }

    #[test]
    fn 首次与最近时间分别记录() {
        let mut t = ConnectionTracker::new();
        let k = key("1.2.3.4", 3389, PortGroup::Tcp);
        t.record(k, 1_000);
        t.record(k, 9_000);
        let e = t.iter_entries().next().unwrap().1;
        assert_eq!(e.first_seen_ms, 1_000);
        assert_eq!(e.last_seen_ms, 9_000);
        assert_eq!(e.count, 2);
    }

    #[test]
    fn 同地址不同端口分别计数() {
        let mut t = ConnectionTracker::new();
        let a = key("1.2.3.4", 3389, PortGroup::Tcp);
        let b = key("1.2.3.4", 80, PortGroup::Web);
        t.record(a, 1_000);
        t.record(a, 1_100);
        assert_eq!(t.record(b, 1_200), 1);
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn 两组保护策略独立计数() {
        let mut t = ConnectionTracker::new();
        let a = key("1.2.3.4", 8080, PortGroup::Tcp);
        let b = key("1.2.3.4", 8080, PortGroup::Web);
        t.record(a, 1_000);
        t.record(b, 1_000);
        t.record(b, 1_010);
        assert_eq!(t.len(), 2);
        let counts: Vec<u32> = t.iter_entries().map(|(_, e)| e.count).collect();
        assert!(counts.contains(&1));
        assert!(counts.contains(&2));
    }

    #[test]
    fn 定期清理过期条目会重置计数() {
        let mut t = ConnectionTracker::new();
        let k = key("1.2.3.4", 3389, PortGroup::Tcp);
        t.record(k, 1_000);
        t.record(k, 2_000);
        // 空闲超过保留期：条目被回收，累计次数一并归零
        assert_eq!(t.prune(100_000, 30_000), 1);
        assert_eq!(t.record(k, 100_100), 1);
    }

    #[test]
    fn 按地址清除全部端口() {
        let mut t = ConnectionTracker::new();
        t.record(key("1.1.1.1", 1, PortGroup::Tcp), 1_000);
        t.record(key("1.1.1.1", 2, PortGroup::Tcp), 1_000);
        t.record(key("3.3.3.3", 1, PortGroup::Tcp), 1_000);
        assert_eq!(
            t.remove_ip(u32::from("1.1.1.1".parse::<std::net::Ipv4Addr>().unwrap())),
            2
        );
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn 条目上限触发淘汰不会无限增长() {
        let mut t = ConnectionTracker::with_max_entries(4);
        for i in 0..100u32 {
            let ip = std::net::Ipv4Addr::from(0x0A00_0000 + i);
            t.record(
                TrackKey {
                    ip: u32::from(ip),
                    port: 3389,
                    group: PortGroup::Tcp,
                },
                i as u64 * 1_000,
            );
        }
        assert!(t.len() <= 4, "实际条目数={}", t.len());
    }

    #[test]
    fn 多源各自累计互不干扰() {
        let mut t = ConnectionTracker::new();
        for round in 0..5u64 {
            for i in 0..3u32 {
                let ip = std::net::Ipv4Addr::from(0xC0A8_0100 + i);
                t.record(
                    TrackKey {
                        ip: u32::from(ip),
                        port: 3389,
                        group: PortGroup::Tcp,
                    },
                    round * 100,
                );
            }
        }
        assert_eq!(t.len(), 3);
        for (_, e) in t.iter_entries() {
            assert_eq!(e.count, 5);
        }
    }
}
