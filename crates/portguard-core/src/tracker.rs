//! 连接行为跟踪器。
//!
//! 职责：按「对端 IP + 本机服务端口 + 保护分组」统计滑动时间窗口内的事件次数。
//!
//! 设计要点：
//! - 时间由调用方注入（`now_ms`），因此完全可单元测试，不依赖真实时钟。
//! - 每个键维护一个时间戳队列，窗口外的时间戳在记录时惰性弹出。
//! - 提供上限保护与显式 `prune`，防止长期运行时条目无限增长（规范 33 稳定性要求）。

use crate::model::PortGroup;
use std::collections::{HashMap, VecDeque};

/// 跟踪键：一个「对端 IP → 本机某端口」的访问关系。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TrackKey {
    /// 对端 IP（大端序 u32）。
    pub ip: u32,
    /// 本机服务端口。
    pub port: u16,
    /// 保护分组（决定使用哪一套窗口与阈值）。
    pub group: PortGroup,
}

/// 单个键的统计状态。
#[derive(Clone, Debug)]
pub struct TrackEntry {
    /// 窗口内事件时间戳（升序）。
    timestamps: VecDeque<u64>,
    /// 首次出现时间。
    pub first_seen_ms: u64,
    /// 最近一次出现时间。
    pub last_seen_ms: u64,
    /// 生命周期内累计事件次数（不随窗口滑出而减少，用于展示与日志）。
    pub total_count: u64,
}

impl TrackEntry {
    fn new(now_ms: u64) -> Self {
        TrackEntry {
            timestamps: VecDeque::with_capacity(8),
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
            total_count: 0,
        }
    }

    /// 当前窗口内计数。
    pub fn window_count(&self) -> u32 {
        self.timestamps.len() as u32
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

    /// 记录一次事件，返回该键在当前窗口内的事件数。
    ///
    /// `window_ms` 由调用方按分组配置传入，因此 TCP / WEB / UDP 可以各自不同。
    pub fn record(&mut self, key: TrackKey, now_ms: u64, window_ms: u64) -> u32 {
        if self.entries.len() >= self.max_entries && !self.entries.contains_key(&key) {
            self.evict_least_recent();
        }
        let entry = self
            .entries
            .entry(key)
            .or_insert_with(|| TrackEntry::new(now_ms));
        entry.last_seen_ms = now_ms;
        entry.total_count = entry.total_count.saturating_add(1);
        entry.timestamps.push_back(now_ms);
        // 惰性淘汰窗口外的时间戳。
        let cutoff = now_ms.saturating_sub(window_ms);
        while let Some(&front) = entry.timestamps.front() {
            if front < cutoff {
                entry.timestamps.pop_front();
            } else {
                break;
            }
        }
        entry.window_count()
    }

    /// 只读查询某键在给定窗口内的当前计数，不产生记录。
    pub fn peek_count(&self, key: &TrackKey, now_ms: u64, window_ms: u64) -> u32 {
        let cutoff = now_ms.saturating_sub(window_ms);
        self.entries
            .get(key)
            .map(|e| e.timestamps.iter().filter(|t| **t >= cutoff).count() as u32)
            .unwrap_or(0)
    }

    /// 全量清理：移除最后活跃时间早于 `retention_ms` 的条目。
    ///
    /// 返回被清理的条目数。应由后台定时任务周期性调用。
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
    fn 窗口内计数递增() {
        let mut t = ConnectionTracker::new();
        let k = key("1.2.3.4", 3389, PortGroup::Tcp);
        assert_eq!(t.record(k, 1_000, 10_000), 1);
        assert_eq!(t.record(k, 2_000, 10_000), 2);
        assert_eq!(t.record(k, 3_000, 10_000), 3);
    }

    #[test]
    fn 窗口滑出后旧事件不再计数() {
        let mut t = ConnectionTracker::new();
        let k = key("1.2.3.4", 3389, PortGroup::Tcp);
        t.record(k, 1_000, 10_000);
        t.record(k, 2_000, 10_000);
        // 时间推进到 20_000，cutoff = 10_000，前两条（1000/2000）滑出
        assert_eq!(t.record(k, 20_000, 10_000), 1);
    }

    #[test]
    fn 生命周期累计计数不受窗口影响() {
        let mut t = ConnectionTracker::new();
        let k = key("1.2.3.4", 3389, PortGroup::Tcp);
        for i in 0..10u64 {
            t.record(k, i * 5_000, 1_000);
        }
        let e = t.iter_entries().next().unwrap().1;
        assert_eq!(e.total_count, 10);
        assert_eq!(e.window_count(), 1);
    }

    #[test]
    fn 同地址不同端口分别计数() {
        let mut t = ConnectionTracker::new();
        let a = key("1.2.3.4", 3389, PortGroup::Tcp);
        let b = key("1.2.3.4", 80, PortGroup::Web);
        t.record(a, 1_000, 10_000);
        t.record(a, 1_100, 10_000);
        assert_eq!(t.record(b, 1_200, 10_000), 1);
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn 两组保护策略独立计数() {
        let mut t = ConnectionTracker::new();
        let a = key("1.2.3.4", 8080, PortGroup::Tcp);
        let b = key("1.2.3.4", 8080, PortGroup::Web);
        t.record(a, 1_000, 10_000);
        t.record(b, 1_000, 10_000);
        t.record(b, 1_010, 10_000);
        assert_eq!(t.peek_count(&a, 1_020, 10_000), 1);
        assert_eq!(t.peek_count(&b, 1_020, 10_000), 2);
    }

    #[test]
    fn 不同时间窗口各自生效() {
        let mut t = ConnectionTracker::new();
        let k = key("9.9.9.9", 53, PortGroup::Udp);
        t.record(k, 1_000, 60_000);
        t.record(k, 2_000, 60_000);
        // 短窗口下两条都已滑出
        assert_eq!(t.peek_count(&k, 100_000, 1_000), 0);
        // 长窗口下仍可见
        assert_eq!(t.peek_count(&k, 3_000, 60_000), 2);
    }

    #[test]
    fn 定期清理过期条目() {
        let mut t = ConnectionTracker::new();
        t.record(key("1.1.1.1", 1, PortGroup::Tcp), 1_000, 10_000);
        t.record(key("2.2.2.2", 1, PortGroup::Tcp), 50_000, 10_000);
        let removed = t.prune(51_000, 30_000);
        assert_eq!(removed, 1);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn 按地址清除全部端口() {
        let mut t = ConnectionTracker::new();
        t.record(key("1.1.1.1", 1, PortGroup::Tcp), 1_000, 10_000);
        t.record(key("1.1.1.1", 2, PortGroup::Tcp), 1_000, 10_000);
        t.record(key("3.3.3.3", 1, PortGroup::Tcp), 1_000, 10_000);
        assert_eq!(t.remove_ip(u32::from("1.1.1.1".parse::<std::net::Ipv4Addr>().unwrap())), 2);
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
                10_000,
            );
        }
        assert!(t.len() <= 4, "实际条目数={}", t.len());
    }

    #[test]
    fn 并发场景下的计数一致性() {
        // 模拟多 IP 混跑：每个 IP 独立达到阈值，互不干扰。
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
                    10_000,
                );
            }
        }
        assert_eq!(t.len(), 3);
        for (_, e) in t.iter_entries() {
            assert_eq!(e.window_count(), 5);
        }
    }
}
