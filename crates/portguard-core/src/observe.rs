//! 抓包观测：把「实际抓到了什么」按「方向 + 协议 + 端口 + 标志类别」分类计数。
//!
//! 存在的唯一理由是可诊断性：当某个受保护端口长期没有任何连接记录时，
//! 必须能区分三种情况，否则只能靠猜：
//!
//! 1. 该端口的包根本没被混杂模式收到（观测里完全没有该端口）；
//! 2. 收到了但标志位不是连接请求（观测里能看到该端口的其它标志，如 `SYN+ACK`）；
//! 3. 收到了但被判定层丢掉（观测里有纯 `SYN`，判定明细里能看到丢弃原因）。
//!
//! 本模块是纯数据结构，不做任何 I/O，条目数有上限（默认 256），
//! 超出后只累加 `overflow`，保证长期运行内存不增长。

use crate::model::{FlagClass, Ip, PacketInfo, Protocol};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 观测条目上限。
pub const MAX_ENTRIES: usize = 256;

/// 观测键：方向 + 协议 + 服务端口 + 标志类别。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ObserveKey {
    inbound: bool,
    protocol: Protocol,
    port: u16,
    flags: FlagClass,
}

/// 一条观测结果（面板展示用）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    /// 是否为入站方向。
    pub inbound: bool,
    pub protocol: Protocol,
    /// 本机侧端口（入站取目的端口，出站取源端口）。
    pub port: u16,
    pub flags: FlagClass,
    /// 观察到的包数。
    pub count: u64,
}

/// 观测表。
#[derive(Debug)]
pub struct Observer {
    entries: HashMap<ObserveKey, u64>,
    overflow: u64,
}

impl Default for Observer {
    fn default() -> Self {
        Observer::new()
    }
}

impl Observer {
    pub fn new() -> Observer {
        Observer {
            entries: HashMap::new(),
            overflow: 0,
        }
    }

    /// 观察一个包。与本机无关的包（非本机 IP）按方向归入「其它」端口 0。
    pub fn observe(&mut self, pkt: &PacketInfo, local_ip: Ip) {
        let inbound = pkt.dst == local_ip;
        let port = if inbound {
            pkt.dst_port
        } else if pkt.src == local_ip {
            pkt.src_port
        } else {
            0
        };
        let flags = match pkt.protocol {
            Protocol::Tcp => pkt.tcp_flags.class(),
            _ => FlagClass::Other,
        };
        let key = ObserveKey {
            inbound,
            protocol: pkt.protocol,
            port,
            flags,
        };
        match self.entries.get_mut(&key) {
            Some(v) => *v = v.saturating_add(1),
            None => {
                if self.entries.len() >= MAX_ENTRIES {
                    // 条目已满：只记总量，避免被扫描流量撑爆内存。
                    self.overflow = self.overflow.saturating_add(1);
                } else {
                    self.entries.insert(key, 1);
                }
            }
        }
    }

    /// 清空观测表（切换网卡后旧数据无意义）。
    pub fn clear(&mut self) {
        self.entries.clear();
        self.overflow = 0;
    }

    /// 因条目上限未被记录的包数。
    pub fn overflow(&self) -> u64 {
        self.overflow
    }

    /// 按次数降序返回前 `limit` 条。
    pub fn top(&self, limit: usize) -> Vec<Observation> {
        let mut rows: Vec<Observation> = self
            .entries
            .iter()
            .map(|(k, count)| Observation {
                inbound: k.inbound,
                protocol: k.protocol,
                port: k.port,
                flags: k.flags,
                count: *count,
            })
            .collect();
        rows.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.port.cmp(&b.port)));
        rows.truncate(limit);
        rows
    }

    /// 统计满足条件的包数（用于自动切换事件来源等判定）。
    pub fn count_matching(&self, f: impl Fn(&Observation) -> bool) -> u64 {
        self.entries
            .iter()
            .filter(|(k, _)| {
                f(&Observation {
                    inbound: k.inbound,
                    protocol: k.protocol,
                    port: k.port,
                    flags: k.flags,
                    count: 0,
                })
            })
            .map(|(_, v)| *v)
            .sum()
    }
}

/// 方向中文标签。
pub fn direction_label(inbound: bool) -> &'static str {
    if inbound {
        "入站"
    } else {
        "出站"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::TcpFlags;

    fn ip(s: &str) -> Ip {
        s.parse().unwrap()
    }

    fn pkt(src: &str, dst: &str, src_port: u16, dst_port: u16, flags: TcpFlags) -> PacketInfo {
        PacketInfo {
            src: ip(src),
            dst: ip(dst),
            src_port,
            dst_port,
            protocol: Protocol::Tcp,
            tcp_flags: flags,
            length: 40,
            timestamp_ms: 0,
        }
    }

    const LOCAL: &str = "10.0.8.8";

    #[test]
    fn 入站与出站分别归类() {
        let mut o = Observer::new();
        // 入站连接请求：dst 是本机，服务端口取目的端口
        o.observe(
            &pkt(
                "1.2.3.4",
                LOCAL,
                51000,
                3389,
                TcpFlags {
                    syn: true,
                    ..Default::default()
                },
            ),
            ip(LOCAL),
        );
        // 出站握手响应：src 是本机，服务端口取源端口
        o.observe(
            &pkt(
                LOCAL,
                "1.2.3.4",
                3389,
                51000,
                TcpFlags {
                    syn: true,
                    ack: true,
                    ..Default::default()
                },
            ),
            ip(LOCAL),
        );
        let rows = o.top(10);
        assert_eq!(rows.len(), 2);
        let inbound = rows.iter().find(|r| r.inbound).expect("应有一条入站记录");
        assert_eq!(inbound.port, 3389);
        assert_eq!(inbound.flags, FlagClass::Syn);
        let outbound = rows.iter().find(|r| !r.inbound).expect("应有一条出站记录");
        assert_eq!(outbound.port, 3389);
        assert_eq!(outbound.flags, FlagClass::SynAck);
    }

    #[test]
    fn 同键累计次数() {
        let mut o = Observer::new();
        for _ in 0..3 {
            o.observe(
                &pkt(
                    "1.2.3.4",
                    LOCAL,
                    51000,
                    3389,
                    TcpFlags {
                        syn: true,
                        ..Default::default()
                    },
                ),
                ip(LOCAL),
            );
        }
        let rows = o.top(10);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].count, 3);
    }

    #[test]
    fn 条目上限不会无限增长() {
        let mut o = Observer::new();
        for port in 0..(MAX_ENTRIES as u16 + 50) {
            o.observe(
                &pkt(
                    "1.2.3.4",
                    LOCAL,
                    51000,
                    port,
                    TcpFlags {
                        syn: true,
                        ..Default::default()
                    },
                ),
                ip(LOCAL),
            );
        }
        assert_eq!(o.top(usize::MAX).len(), MAX_ENTRIES);
        assert_eq!(o.overflow(), 50);
        o.clear();
        assert_eq!(o.top(10).len(), 0);
        assert_eq!(o.overflow(), 0);
    }

    #[test]
    fn 可按条件统计服务端口() {
        let mut o = Observer::new();
        let syn = TcpFlags {
            syn: true,
            ..Default::default()
        };
        let syn_ack = TcpFlags {
            syn: true,
            ack: true,
            ..Default::default()
        };
        o.observe(&pkt("1.2.3.4", LOCAL, 51000, 3389, syn), ip(LOCAL));
        o.observe(&pkt(LOCAL, "1.2.3.4", 3389, 52000, syn_ack), ip(LOCAL));
        o.observe(&pkt(LOCAL, "1.2.3.4", 3389, 52000, syn_ack), ip(LOCAL));
        assert_eq!(
            o.count_matching(|r| r.inbound && r.port == 3389 && r.flags == FlagClass::Syn),
            1
        );
        assert_eq!(
            o.count_matching(|r| !r.inbound && r.port == 3389 && r.flags == FlagClass::SynAck),
            2
        );
    }

    #[test]
    fn 非本机流量归入端口零() {
        let mut o = Observer::new();
        o.observe(
            &pkt(
                "10.0.0.6",
                "10.0.0.7",
                1000,
                2000,
                TcpFlags {
                    syn: true,
                    ..Default::default()
                },
            ),
            ip(LOCAL),
        );
        let rows = o.top(10);
        assert_eq!(rows[0].port, 0);
        assert!(!rows[0].inbound);
    }
}
