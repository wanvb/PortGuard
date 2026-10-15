//! 规则引擎。
//!
//! 纯决策模块：输入一个 `PacketInfo`，输出一个 `Outcome`，不碰防火墙、不写磁盘、
//! 不依赖 Windows API。所有分支均可用单元测试覆盖（规范 30）。
//!
//! 判定顺序严格遵循规范 5.1：
//!
//! ```text
//! 白名单  →  黑名单  →  保护端口  →  次数阈值  →  封停
//! ```

use crate::config::{Config, ProtectionRule};
use crate::iprange::IpSet;
use crate::model::{IgnoreCounters, Ip, PacketInfo, PortGroup, Protocol, TcpFlags};
use crate::tracker::{ConnectionTracker, TrackKey};

/// 原始 TCP 标志位常量集合，便于构造测试数据。
pub const FLAG_SYN: TcpFlags = TcpFlags {
    syn: true,
    ack: false,
    fin: false,
    rst: false,
    psh: false,
    urg: false,
};

/// 65536 位端口表。使用 `Box<[bool; 65536]>`（64 KiB）换取 O(1) 判定，
/// 比 HashSet 更省且无哈希开销（规范 21）。
#[derive(Debug)]
struct PortMask {
    bits: Box<[bool; 65536]>,
}

impl PortMask {
    fn new() -> Self {
        PortMask {
            bits: Box::new([false; 65536]),
        }
    }

    fn build(ports: &[u16]) -> Self {
        let mut m = PortMask::new();
        for p in ports {
            m.bits[*p as usize] = true;
        }
        m
    }

    #[inline]
    fn contains(&self, port: u16) -> bool {
        self.bits[port as usize]
    }

    fn count(&self) -> usize {
        self.bits.iter().filter(|b| **b).count()
    }
}

/// 单包判定结果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// 命中白名单：永远放行，即使同时命中黑名单或已超阈值。
    Whitelisted,
    /// 命中黑名单：立即封停。
    BlacklistBan,
    /// 未达阈值，已计入统计。
    Tracking {
        group: PortGroup,
        count: u32,
        threshold: u32,
    },
    /// 累计次数达到阈值：应封停。
    ThresholdBan {
        group: PortGroup,
        count: u32,
        threshold: u32,
    },
    /// 与本机受保护端口无关，或不是有效的连接建立事件。
    Ignored { reason: &'static str },
}

impl Outcome {
    /// 是否应当触发封停（供上层控制器直接判断）。
    pub fn should_ban(&self) -> bool {
        matches!(
            self,
            Outcome::BlacklistBan | Outcome::ThresholdBan { .. }
        )
    }
}

/// 引擎累计统计。
#[derive(Clone, Copy, Debug, Default)]
pub struct EngineStats {
    /// 累计处理的数据包。
    pub packets: u64,
    /// 白名单放行次数。
    pub whitelisted: u64,
    /// 黑名单命中次数。
    pub blacklist_hits: u64,
    /// 计入跟踪的事件数。
    pub tracked_events: u64,
    /// 超阈值次数。
    pub threshold_hits: u64,
    /// 被忽略的数据包按原因计数。
    ///
    /// 这是排查「保护端口收不到任何连接」的第一手证据：抓包数在涨、
    /// 但某个忽略计数同步在涨，说明问题出在判定条件而非抓包链路。
    pub ignored: IgnoreCounters,
}

/// 「当前连接」视图行，供 Web 面板展示。
#[derive(Clone, Debug)]
pub struct ConnectionRow {
    pub ip: Ip,
    pub port: u16,
    pub group: PortGroup,
    /// 累计连接次数（判定阈值用的就是这个值）。
    pub count: u32,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

/// 规则引擎。
#[derive(Debug)]
pub struct RuleEngine {
    /// 本机被监听的 IPv4 地址。
    local_ip: Ip,
    whitelist: IpSet,
    blacklist: IpSet,
    tcp_mask: PortMask,
    web_mask: PortMask,
    udp_mask: PortMask,
    tcp_rule: ProtectionRule,
    web_rule: ProtectionRule,
    udp_rule: ProtectionRule,
    /// 是否把流出方向也计入阈值。
    ///
    /// 默认 `false`：只统计「外部 → 本机受保护端口」的入站请求，
    /// 这是暴力破解与扫描的真实特征；把本机主动外连计入会误伤正常业务。
    count_outbound: bool,
    /// 是否把「服务端握手响应（SYN+ACK）」当成一次连接事件。
    ///
    /// 只有本机对受保护端口的入站连接才会发出这种包，因此不存在误伤；
    /// 用于混杂模式收不到入站包的环境（详见 `ProtectConfig::count_accept`）。
    /// 与入站 `SYN && !ACK` **互斥**，同一连接只会被计一次。
    count_accept: bool,
    /// 连接跟踪器。
    pub tracker: ConnectionTracker,
    stats: EngineStats,
}

impl RuleEngine {
    /// 依据配置构造引擎。
    pub fn new(cfg: &Config, local_ip: Ip) -> Self {
        let mut engine = RuleEngine {
            local_ip,
            whitelist: IpSet::default(),
            blacklist: IpSet::default(),
            tcp_mask: PortMask::new(),
            web_mask: PortMask::new(),
            udp_mask: PortMask::new(),
            tcp_rule: ProtectionRule::default(),
            web_rule: ProtectionRule::default(),
            udp_rule: ProtectionRule::default(),
            count_outbound: false,
            count_accept: cfg.protect.count_accept,
            tracker: ConnectionTracker::new(),
            stats: EngineStats::default(),
        };
        engine.reload(cfg);
        engine
    }

    /// 热更新配置（白名单解析失败时保留旧值，不静默清空规则）。
    pub fn reload(&mut self, cfg: &Config) {
        if let Ok(wl) = IpSet::from_rules(&cfg.lists.whitelist) {
            self.whitelist = wl;
        }
        if let Ok(bl) = IpSet::from_rules(&cfg.lists.blacklist) {
            self.blacklist = bl;
        }
        self.count_accept = cfg.protect.count_accept;
        self.tcp_rule = cfg.protect.tcp.clone();
        self.web_rule = cfg.protect.http.clone();
        self.udp_rule = cfg.protect.udp.clone();
        self.tcp_mask = PortMask::build(&self.tcp_rule.ports);
        self.web_mask = PortMask::build(&self.web_rule.ports);
        self.udp_mask = PortMask::build(&self.udp_rule.ports);
    }

    /// 切换监听 IP，并清空既有跟踪状态（换网卡后旧计数无意义）。
    pub fn set_local_ip(&mut self, ip: Ip) {
        self.local_ip = ip;
        self.tracker.clear();
    }

    pub fn local_ip(&self) -> Ip {
        self.local_ip
    }

    pub fn set_count_outbound(&mut self, v: bool) {
        self.count_outbound = v;
    }

    /// 设置是否把服务端握手响应（SYN+ACK）当作连接事件。
    pub fn set_count_accept(&mut self, v: bool) {
        self.count_accept = v;
    }

    pub fn count_accept(&self) -> bool {
        self.count_accept
    }

    /// 该 TCP 包是否算「一次连接事件」。
    ///
    /// 两种事件来源**互斥**（`docs/behavior-spec.md` 2.5）：
    /// `count_accept` 关闭时只认入站 `SYN && !ACK`；打开时改用本机发出的 `SYN+ACK`。
    /// 不得两路同时累加 —— 同一次连接会先按请求、再按应答各计一次，阈值事实上折半。
    fn is_connection_event(&self, pkt: &PacketInfo, inbound: bool) -> bool {
        if self.count_accept {
            !inbound && pkt.tcp_flags.is_handshake_accepted()
        } else {
            inbound && pkt.tcp_flags.is_connection_request()
        }
    }

    pub fn stats(&self) -> EngineStats {
        self.stats
    }

    /// 白名单是否命中（供上层做「加白即解封」联动）。
    pub fn is_whitelisted(&self, ip: Ip) -> bool {
        self.whitelist.contains(ip)
    }

    /// 受保护端口总数，用于面板展示。
    pub fn protected_port_count(&self) -> usize {
        self.tcp_mask.count() + self.web_mask.count() + self.udp_mask.count()
    }

    /// 判定单个数据包。
    pub fn evaluate(&mut self, pkt: &PacketInfo) -> Outcome {
        self.stats.packets = self.stats.packets.saturating_add(1);

        if pkt.protocol == Protocol::Icmp {
            self.count_ignored(|c| c.icmp += 1);
            return Outcome::Ignored {
                reason: "icmp_unsupported",
            };
        }

        let inbound = pkt.dst == self.local_ip;
        let outbound = pkt.src == self.local_ip;
        if !inbound && !outbound {
            // SIO_RCVALL 会收到网段内所有流量，非本机流量直接忽略。
            self.count_ignored(|c| c.not_local += 1);
            return Outcome::Ignored {
                reason: "not_local_traffic",
            };
        }
        // 服务端握手响应（SYN+ACK）虽属流出方向，但只可能是「别人连到本机受保护端口」
        // 的应答，故在 count_accept 打开时放行，不算作本机主动外连。
        // （是否真的计一次连接由 `is_connection_event` 判断，这里只是别把它当外连丢掉。）
        let accept_signal =
            self.count_accept && pkt.protocol == Protocol::Tcp && pkt.tcp_flags.is_handshake_accepted();
        if outbound && !self.count_outbound && !accept_signal {
            self.count_ignored(|c| c.outbound += 1);
            return Outcome::Ignored {
                reason: "outbound_ignored",
            };
        }

        let peer: Ip = if inbound { pkt.src } else { pkt.dst };
        let service_port = if inbound { pkt.dst_port } else { pkt.src_port };
        // 是否算一次连接事件。白名单的展示记录与阈值计数共用同一判据，
        // 避免两处口径漂移（历史上这里曾分头判断）。
        let tcp_event = self.is_connection_event(pkt, inbound);

        // ① 白名单最高优先级：只统计、永不封停。
        if self.whitelist.contains(peer) {
            self.stats.whitelisted = self.stats.whitelisted.saturating_add(1);
            // 白名单不参与阈值判定，但要留下展示记录：否则面板上的 WHITELIST 状态
            // 永远不可达，用户会误以为「白名单里的地址从来没连过」。
            let countable = match pkt.protocol {
                Protocol::Tcp => tcp_event,
                Protocol::Udp => true,
                Protocol::Icmp => false,
            };
            if countable {
                self.record_display_only(peer, service_port, pkt.timestamp_ms, pkt.protocol);
            }
            return Outcome::Whitelisted;
        }
        // ② 黑名单立即封停。
        if self.blacklist.contains(peer) {
            self.stats.blacklist_hits = self.stats.blacklist_hits.saturating_add(1);
            return Outcome::BlacklistBan;
        }

        // ③ 保护端口 + 阈值。TCP 必须由 SYN && !ACK 触发。
        match pkt.protocol {
            Protocol::Tcp => {
                // 连接事件来源二选一，见 `is_connection_event`。
                if !tcp_event {
                    self.count_ignored(|c| c.not_new_connection += 1);
                    return Outcome::Ignored {
                        reason: "not_new_connection",
                    };
                }
                // TCP 与 WEB 是两套独立配置，端口重合时两组**都要计数**，
                // 任意一组超限即封停；都未超限时返回 TCP 组的结果作为代表。
                let mut result = Outcome::Ignored {
                    reason: "port_not_protected",
                };
                if self.tcp_mask.contains(service_port) {
                    let key = TrackKey {
                        ip: u32::from(peer),
                        port: service_port,
                        group: PortGroup::Tcp,
                    };
                    let out = self.record_and_judge(
                        key,
                        pkt.timestamp_ms,
                        PortGroup::Tcp,
                        self.tcp_rule.max_attempts,
                    );
                    if out.should_ban() {
                        return out;
                    }
                    result = out;
                }
                if self.web_mask.contains(service_port) {
                    let web_key = TrackKey {
                        ip: u32::from(peer),
                        port: service_port,
                        group: PortGroup::Web,
                    };
                    let out = self.record_and_judge(
                        web_key,
                        pkt.timestamp_ms,
                        PortGroup::Web,
                        self.web_rule.max_attempts,
                    );
                    if out.should_ban() {
                        return out;
                    }
                    if matches!(result, Outcome::Ignored { .. }) {
                        result = out;
                    }
                }
                if matches!(result, Outcome::Ignored { .. }) {
                    self.count_ignored(|c| c.port_not_protected += 1);
                }
                result
            }
            Protocol::Udp => {
                // UDP 无连接建立过程，每个报文都记一次访问（规范 4.3）。
                if !self.udp_mask.contains(service_port) {
                    self.count_ignored(|c| c.port_not_protected += 1);
                    return Outcome::Ignored {
                        reason: "port_not_protected",
                    };
                }
                let key = TrackKey {
                    ip: u32::from(peer),
                    port: service_port,
                    group: PortGroup::Udp,
                };
                self.record_and_judge(
                    key,
                    pkt.timestamp_ms,
                    PortGroup::Udp,
                    self.udp_rule.max_attempts,
                )
            }
            Protocol::Icmp => {
                self.count_ignored(|c| c.icmp += 1);
                Outcome::Ignored {
                    reason: "icmp_unsupported",
                }
            }
        }
    }

    /// 原子地累加某个忽略计数（饱和，不 panic）。
    fn count_ignored<F: FnOnce(&mut IgnoreCounters)>(&mut self, f: F) {
        f(&mut self.stats.ignored);
    }

    /// 服务端口所属的保护组。
    ///
    /// 端口同时属于 TCP 与 WEB 时取 TCP（与 `evaluate` 的「TCP 优先作为代表」一致），
    /// 仅供展示使用。
    fn group_of_port(&self, port: u16, protocol: Protocol) -> Option<PortGroup> {
        match protocol {
            Protocol::Tcp => {
                if self.tcp_mask.contains(port) {
                    Some(PortGroup::Tcp)
                } else if self.web_mask.contains(port) {
                    Some(PortGroup::Web)
                } else {
                    None
                }
            }
            Protocol::Udp => {
                if self.udp_mask.contains(port) {
                    Some(PortGroup::Udp)
                } else {
                    None
                }
            }
            Protocol::Icmp => None,
        }
    }

    /// 只写跟踪表、不参与阈值判定的展示记录（白名单专用）。
    ///
    /// 端口不在任何保护组时不记录：白名单 IP 访问非保护端口对用户没有意义，
    /// 记下来只会让连接列表被无关行淹没。
    fn record_display_only(&mut self, peer: Ip, service_port: u16, now_ms: u64, protocol: Protocol) {
        let group = match self.group_of_port(service_port, protocol) {
            Some(g) => g,
            None => return,
        };
        let key = TrackKey {
            ip: u32::from(peer),
            port: service_port,
            group,
        };
        let _ = self.tracker.record(key, now_ms);
    }

    /// 记录一次事件并按所属组判定。
    ///
    /// TCP / TCP-WEB / UDP 三组的判定逻辑完全一致，只差「用哪组阈值」与
    /// 「归入哪个组」，故合并为单一实现：三份平行代码各自演化容易埋下行为偏差。
    /// 阈值由调用方传入，避免在持有 `&mut self.tracker` 时再借 `self.*_rule`。
    ///
    /// 判定用**累计次数**而非滑动窗口：阈值 N 表示第 N 次连接即封停（`count >= N`）。
    fn record_and_judge(
        &mut self,
        key: TrackKey,
        now_ms: u64,
        group: PortGroup,
        threshold: u32,
    ) -> Outcome {
        let count = self.tracker.record(key, now_ms);
        self.stats.tracked_events = self.stats.tracked_events.saturating_add(1);
        if count >= threshold {
            self.stats.threshold_hits = self.stats.threshold_hits.saturating_add(1);
            Outcome::ThresholdBan {
                group,
                count,
                threshold,
            }
        } else {
            Outcome::Tracking {
                group,
                count,
                threshold,
            }
        }
    }

    /// 顶点的当前连接快照，只保留最近 `ttl_ms` 内活跃的记录。
    pub fn connection_rows(&self, now_ms: u64, ttl_ms: u64) -> Vec<ConnectionRow> {
        let cutoff = now_ms.saturating_sub(ttl_ms);
        let mut rows: Vec<ConnectionRow> = self
            .tracker
            .iter_entries()
            .filter(|(_, e)| e.last_seen_ms >= cutoff)
            .map(|(k, e)| ConnectionRow {
                ip: crate::iprange::u32_to_ip(k.ip),
                port: k.port,
                group: k.group,
                count: e.count,
                first_seen_ms: e.first_seen_ms,
                last_seen_ms: e.last_seen_ms,
            })
            .collect();
        // 次数优先、时间其次，保证面板排序稳定。
        rows.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| b.last_seen_ms.cmp(&a.last_seen_ms))
        });
        rows
    }

    /// 定期清理跟踪状态，防止长期运行内存增长。
    pub fn prune(&mut self, now_ms: u64, retention_ms: u64) -> usize {
        self.tracker.prune(now_ms, retention_ms)
    }

    /// 清空跟踪状态。
    pub fn reset_tracking(&mut self) {
        self.tracker.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProtectionRule;

    fn ip(s: &str) -> Ip {
        s.parse().unwrap()
    }

    const LOCAL: &str = "192.168.1.10";
    const PEER: &str = "203.0.113.9";

    fn base_config() -> Config {
        let mut c = Config::with_defaults();
        // 本文件绝大多数用例走「入站 SYN」口径，显式关掉默认开启的握手响应来源；
        // 握手响应路径另有专门用例（`默认开启统计服务端应答` 等）。
        c.protect.count_accept = false;
        c.protect.tcp = ProtectionRule {
            ports: vec![3389],
            max_attempts: 3,
        };
        c.protect.http = ProtectionRule {
            ports: vec![80],
            max_attempts: 5,
        };
        c.protect.udp = ProtectionRule {
            ports: vec![53],
            max_attempts: 2,
        };
        c
    }

    /// 构造一个「外部 → 本机受保护端口」的 TCP SYN 包。
    fn syn_packet(src: &str, dst_port: u16, ts: u64) -> PacketInfo {
        PacketInfo {
            src: ip(src),
            dst: ip(LOCAL),
            src_port: 44444,
            dst_port,
            protocol: Protocol::Tcp,
            tcp_flags: FLAG_SYN,
            length: 40,
            timestamp_ms: ts,
        }
    }

    fn engine() -> RuleEngine {
        RuleEngine::new(&base_config(), ip(LOCAL))
    }

    #[test]
    fn 白名单永远放行() {
        let mut cfg = base_config();
        cfg.lists.whitelist = vec!["203.0.113.*".to_string()];
        let mut e = RuleEngine::new(&cfg, ip(LOCAL));
        for i in 0..100 {
            let out = e.evaluate(&syn_packet(PEER, 3389, i * 100));
            assert_eq!(out, Outcome::Whitelisted);
        }
        assert_eq!(e.stats().threshold_hits, 0, "白名单不得被自动封停");
    }

    #[test]
    fn 白名单优先于黑名单() {
        let mut cfg = base_config();
        cfg.lists.whitelist = vec!["203.0.113.9".to_string()];
        cfg.lists.blacklist = vec!["203.0.113.9".to_string()];
        let mut e = RuleEngine::new(&cfg, ip(LOCAL));
        assert_eq!(e.evaluate(&syn_packet(PEER, 3389, 1_000)), Outcome::Whitelisted);
    }

    #[test]
    fn 黑名单立即封停不计数() {
        let mut cfg = base_config();
        cfg.lists.blacklist = vec!["203.0.113.0-203.0.113.255".to_string()];
        let mut e = RuleEngine::new(&cfg, ip(LOCAL));
        assert_eq!(e.evaluate(&syn_packet(PEER, 3389, 1_000)), Outcome::BlacklistBan);
        assert_eq!(e.tracker.len(), 0);
    }

    #[test]
    fn 未达阈值只跟踪() {
        let mut e = engine();
        assert!(matches!(
            e.evaluate(&syn_packet(PEER, 3389, 1_000)),
            Outcome::Tracking { count: 1, threshold: 3, .. }
        ));
        assert!(matches!(
            e.evaluate(&syn_packet(PEER, 3389, 2_000)),
            Outcome::Tracking { count: 2, threshold: 3, .. }
        ));
    }

    #[test]
    fn 累计达到阈值即封停() {
        let mut e = engine();
        for i in 0..2u64 {
            e.evaluate(&syn_packet(PEER, 3389, i * 1_000));
        }
        // 阈值 3：第 3 次连接（含本次）即封停
        match e.evaluate(&syn_packet(PEER, 3389, 2_000)) {
            Outcome::ThresholdBan {
                group,
                count,
                threshold,
            } => {
                assert_eq!(group, PortGroup::Tcp);
                assert_eq!(count, 3);
                assert_eq!(threshold, 3);
            }
            other => panic!("期望达到阈值封停，实际={:?}", other),
        }
    }

    #[test]
    fn 累计计数不因时间间隔归零() {
        // 滑动窗口在这里会归零 → 反复但稀疏的连接永远够不到阈值（漏封）。
        let mut e = engine();
        e.evaluate(&syn_packet(PEER, 3389, 1_000));
        e.evaluate(&syn_packet(PEER, 3389, 2_000));
        // 隔 5 分钟再连一次，累计值继续增长并触发封停
        let out = e.evaluate(&syn_packet(PEER, 3389, 300_000));
        assert!(matches!(
            out,
            Outcome::ThresholdBan {
                count: 3,
                threshold: 3,
                ..
            }
        ));
    }

    #[test]
    fn 握手响应不算新连接() {
        let mut e = engine();
        let mut pkt = syn_packet(PEER, 3389, 1_000);
        pkt.tcp_flags = TcpFlags {
            syn: true,
            ack: true,
            ..Default::default()
        };
        assert_eq!(
            e.evaluate(&pkt),
            Outcome::Ignored {
                reason: "not_new_connection"
            }
        );
        assert_eq!(e.tracker.len(), 0);
    }

    #[test]
    fn 仅确认与结束标志不计入() {
        let mut e = engine();
        let mut pkt = syn_packet(PEER, 3389, 1_000);
        pkt.tcp_flags = TcpFlags {
            ack: true,
            fin: true,
            ..Default::default()
        };
        assert!(matches!(e.evaluate(&pkt), Outcome::Ignored { .. }));
        assert_eq!(e.tracker.len(), 0);
    }

    #[test]
    fn 非保护端口被忽略() {
        let mut e = engine();
        let out = e.evaluate(&syn_packet(PEER, 8080, 1_000));
        assert_eq!(
            out,
            Outcome::Ignored {
                reason: "port_not_protected"
            }
        );
    }

    #[test]
    fn 非本机流量被忽略() {
        let mut e = engine();
        let mut pkt = syn_packet(PEER, 3389, 1_000);
        pkt.dst = ip("10.0.0.5");
        pkt.src = ip("10.0.0.6");
        assert_eq!(
            e.evaluate(&pkt),
            Outcome::Ignored {
                reason: "not_local_traffic"
            }
        );
    }

    #[test]
    fn 本机外连默认不计入() {
        let mut e = engine();
        let mut pkt = syn_packet(PEER, 3389, 1_000);
        pkt.src = ip(LOCAL);
        pkt.dst = ip(PEER);
        pkt.src_port = 3389;
        pkt.dst_port = 55555;
        assert_eq!(
            e.evaluate(&pkt),
            Outcome::Ignored {
                reason: "outbound_ignored"
            }
        );
    }

    #[test]
    fn 网页端口组使用独立阈值() {
        let mut cfg = base_config();
        cfg.protect.http.max_attempts = 2;
        cfg.protect.tcp = ProtectionRule {
            ports: vec![],
            max_attempts: 99,
        };
        let mut e = RuleEngine::new(&cfg, ip(LOCAL));
        e.evaluate(&syn_packet(PEER, 80, 1_000));
        let out = e.evaluate(&syn_packet(PEER, 80, 1_100));
        assert!(matches!(
            out,
            Outcome::ThresholdBan {
                group: PortGroup::Web,
                count: 2,
                threshold: 2
            }
        ));
    }

    #[test]
    fn 同端口同时属于两组时两组独立计数() {
        let mut cfg = base_config();
        cfg.protect.tcp = ProtectionRule {
            ports: vec![8080],
            max_attempts: 99,
        };
        cfg.protect.http = ProtectionRule {
            ports: vec![8080],
            max_attempts: 2,
        };
        let mut e = RuleEngine::new(&cfg, ip(LOCAL));
        e.evaluate(&syn_packet(PEER, 8080, 1_000));
        let out = e.evaluate(&syn_packet(PEER, 8080, 1_100));
        // TCP 阈值 99 未到，WEB 阈值 2 已达
        assert!(matches!(
            out,
            Outcome::ThresholdBan {
                group: PortGroup::Web,
                ..
            }
        ));
    }

    /// 构造「本机受保护端口 → 对端」的 TCP SYN+ACK（服务端握手响应）。
    fn syn_ack_packet(peer: &str, local_port: u16, ts: u64) -> PacketInfo {
        PacketInfo {
            src: ip(LOCAL),
            dst: ip(peer),
            src_port: local_port,
            dst_port: 50000,
            protocol: Protocol::Tcp,
            tcp_flags: TcpFlags {
                syn: true,
                ack: true,
                ..Default::default()
            },
            length: 40,
            timestamp_ms: ts,
        }
    }

    #[test]
    fn 默认不把握手响应计为连接事件() {
        let mut e = engine();
        assert_eq!(
            e.evaluate(&syn_ack_packet(PEER, 3389, 1_000)),
            Outcome::Ignored {
                reason: "outbound_ignored"
            }
        );
        assert_eq!(e.tracker.len(), 0);
    }

    #[test]
    fn 默认开启统计服务端应答() {
        // 默认配置（不再显式关闭）下事件来源即为握手响应，入站 SYN 不再计数
        let cfg = Config::with_defaults();
        let mut e = RuleEngine::new(&cfg, ip(LOCAL));
        assert!(e.count_accept(), "默认应统计服务端应答");
        assert_eq!(
            e.evaluate(&syn_packet(PEER, 3389, 1_000)),
            Outcome::Ignored {
                reason: "not_new_connection"
            },
            "开启后入站 SYN 不再作为连接事件"
        );
        assert!(matches!(
            e.evaluate(&syn_ack_packet(PEER, 3389, 1_100)),
            Outcome::Tracking { count: 1, .. }
        ));
    }

    #[test]
    fn 两种事件来源互斥不会重复计数() {
        // 同一次连接：先到入站 SYN，再发出 SYN+ACK。开启开关后只应计一次。
        let mut cfg = base_config();
        cfg.protect.count_accept = true;
        let mut e = RuleEngine::new(&cfg, ip(LOCAL));
        e.evaluate(&syn_packet(PEER, 3389, 1_000));
        let out = e.evaluate(&syn_ack_packet(PEER, 3389, 1_010));
        assert!(
            matches!(out, Outcome::Tracking { count: 1, threshold: 3, .. }),
            "同一次连接不得被计两次：{:?}",
            out
        );
        assert_eq!(e.connection_rows(2_000, 60_000)[0].count, 1);
    }

    #[test]
    fn 开启后握手响应计为一次连接() {
        let mut cfg = base_config();
        cfg.protect.count_accept = true;
        let mut e = RuleEngine::new(&cfg, ip(LOCAL));
        for i in 0..2u64 {
            assert!(matches!(
                e.evaluate(&syn_ack_packet(PEER, 3389, i * 100)),
                Outcome::Tracking {
                    group: PortGroup::Tcp,
                    ..
                }
            ));
        }
        // 阈值 3：第 3 次即封停
        assert!(matches!(
            e.evaluate(&syn_ack_packet(PEER, 3389, 200)),
            Outcome::ThresholdBan {
                group: PortGroup::Tcp,
                count: 3,
                threshold: 3
            }
        ));
        let rows = e.connection_rows(400, 60_000);
        assert_eq!(rows.len(), 1, "服务端口应取本机端口 3389");
        assert_eq!(rows[0].port, 3389);
        assert_eq!(rows[0].ip, ip(PEER));
    }

    #[test]
    fn 开启后本机主动外连仍不计入() {
        let mut cfg = base_config();
        cfg.protect.count_accept = true;
        let mut e = RuleEngine::new(&cfg, ip(LOCAL));
        // 本机主动连接对端 3389：源端口是临时端口，发出的纯 SYN 不属于握手响应
        let mut pkt = syn_packet(PEER, 3389, 1_000);
        pkt.src = ip(LOCAL);
        pkt.dst = ip(PEER);
        pkt.src_port = 55555;
        pkt.dst_port = 3389;
        assert_eq!(
            e.evaluate(&pkt),
            Outcome::Ignored {
                reason: "outbound_ignored"
            }
        );
        assert_eq!(e.tracker.len(), 0);
    }

    #[test]
    fn 开启后非保护端口握手响应仍被忽略() {
        let mut cfg = base_config();
        cfg.protect.count_accept = true;
        let mut e = RuleEngine::new(&cfg, ip(LOCAL));
        assert_eq!(
            e.evaluate(&syn_ack_packet(PEER, 8080, 1_000)),
            Outcome::Ignored {
                reason: "port_not_protected"
            }
        );
        assert_eq!(e.stats().ignored.port_not_protected, 1);
    }

    #[test]
    fn 用户数据报每个报文都计数() {
        let mut e = engine();
        let pkt = PacketInfo {
            src: ip(PEER),
            dst: ip(LOCAL),
            src_port: 40000,
            dst_port: 53,
            protocol: Protocol::Udp,
            tcp_flags: TcpFlags::default(),
            length: 60,
            timestamp_ms: 1_000,
        };
        assert!(matches!(
            e.evaluate(&pkt),
            Outcome::Tracking {
                group: PortGroup::Udp,
                count: 1,
                ..
            }
        ));
        let pkt2 = PacketInfo {
            timestamp_ms: 1_100,
            ..pkt
        };
        // 阈值 2：第 2 个报文即封停
        assert!(matches!(
            e.evaluate(&pkt2),
            Outcome::ThresholdBan {
                group: PortGroup::Udp,
                count: 2,
                threshold: 2
            }
        ));
    }

    #[test]
    fn 网际控制报文被忽略() {
        let mut e = engine();
        let pkt = PacketInfo {
            src: ip(PEER),
            dst: ip(LOCAL),
            src_port: 0,
            dst_port: 0,
            protocol: Protocol::Icmp,
            tcp_flags: TcpFlags::default(),
            length: 28,
            timestamp_ms: 1_000,
        };
        assert!(matches!(e.evaluate(&pkt), Outcome::Ignored { .. }));
    }

    #[test]
    fn 切换监听地址会清空跟踪状态() {
        let mut e = engine();
        e.evaluate(&syn_packet(PEER, 3389, 1_000));
        assert_eq!(e.tracker.len(), 1);
        e.set_local_ip(ip("10.0.0.1"));
        assert_eq!(e.tracker.len(), 0);
    }

    #[test]
    fn 非法白名单不会清空既有规则() {
        let mut cfg = base_config();
        cfg.lists.whitelist = vec!["203.0.113.*".to_string()];
        let mut e = RuleEngine::new(&cfg, ip(LOCAL));
        assert!(e.is_whitelisted(ip(PEER)));
        // 灌入非法配置，旧的合法白名单必须保留
        cfg.lists.whitelist = vec!["这不是IP".to_string()];
        e.reload(&cfg);
        assert!(e.is_whitelisted(ip(PEER)), "非法配置不得清空既有白名单");
    }

    #[test]
    fn 并发多源互不干扰() {
        let mut e = engine();
        for i in 0..2u64 {
            e.evaluate(&syn_packet("198.51.100.1", 3389, i * 100));
            e.evaluate(&syn_packet("198.51.100.2", 3389, i * 100));
        }
        // 两个源各 2 次，都还没到阈值 3
        assert_eq!(e.stats().threshold_hits, 0);
        assert_eq!(e.tracker.len(), 2);
        let rows = e.connection_rows(1_000, 60_000);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].count, 2);
    }

    #[test]
    fn 连接快照按次数降序() {
        let mut e = engine();
        e.evaluate(&syn_packet("198.51.100.1", 3389, 1_000));
        e.evaluate(&syn_packet("198.51.100.2", 3389, 1_000));
        e.evaluate(&syn_packet("198.51.100.2", 3389, 1_100));
        let rows = e.connection_rows(1_200, 60_000);
        assert_eq!(rows[0].ip, ip("198.51.100.2"));
        assert_eq!(rows[0].count, 2);
    }

    #[test]
    fn 快照过滤过期行() {
        let mut e = engine();
        e.evaluate(&syn_packet(PEER, 3389, 1_000));
        assert_eq!(e.connection_rows(1_000, 60_000).len(), 1);
        assert_eq!(e.connection_rows(999_999, 60_000).len(), 0);
    }

    #[test]
    fn 保护端口计数正确() {
        let e = engine();
        // tcp 1 个 + web 1 个 + udp 1 个
        assert_eq!(e.protected_port_count(), 3);
    }

    #[test]
    fn 忽略原因分别计数() {
        let mut e = engine();
        // 非本机流量
        let mut pkt = syn_packet(PEER, 3389, 1_000);
        pkt.src = ip("10.0.0.6");
        pkt.dst = ip("10.0.0.7");
        e.evaluate(&pkt);
        // 本机外连
        let mut out = syn_packet(PEER, 3389, 1_000);
        out.src = ip(LOCAL);
        out.dst = ip(PEER);
        out.src_port = 3389;
        out.dst_port = 55555;
        e.evaluate(&out);
        // 非新建连接
        let mut ack = syn_packet(PEER, 3389, 1_000);
        ack.tcp_flags = TcpFlags {
            ack: true,
            ..Default::default()
        };
        e.evaluate(&ack);
        // 端口未保护
        e.evaluate(&syn_packet(PEER, 8080, 1_000));
        // ICMP
        let icmp = PacketInfo {
            src: ip(PEER),
            dst: ip(LOCAL),
            src_port: 0,
            dst_port: 0,
            protocol: Protocol::Icmp,
            tcp_flags: TcpFlags::default(),
            length: 28,
            timestamp_ms: 1_000,
        };
        e.evaluate(&icmp);

        let ig = e.stats().ignored;
        assert_eq!(ig.not_local, 1);
        assert_eq!(ig.outbound, 1);
        assert_eq!(ig.not_new_connection, 1);
        assert_eq!(ig.port_not_protected, 1);
        assert_eq!(ig.icmp, 1);
    }

    #[test]
    fn 白名单地址留下展示记录但绝不封停() {
        let mut cfg = base_config();
        cfg.lists.whitelist = vec!["203.0.113.*".to_string()];
        let mut e = RuleEngine::new(&cfg, ip(LOCAL));
        for i in 0..10u64 {
            assert_eq!(
                e.evaluate(&syn_packet(PEER, 3389, i * 1_000)),
                Outcome::Whitelisted
            );
        }
        // 面板需要能看到白名单地址的访问，故仍进跟踪表
        let rows = e.connection_rows(9_000, 60_000);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ip, ip(PEER));
        assert_eq!(rows[0].count, 10);
        assert_eq!(e.stats().threshold_hits, 0, "白名单不得被自动封停");
    }

    #[test]
    fn 白名单访问非保护端口不留记录() {
        let mut cfg = base_config();
        cfg.lists.whitelist = vec!["203.0.113.*".to_string()];
        let mut e = RuleEngine::new(&cfg, ip(LOCAL));
        assert_eq!(
            e.evaluate(&syn_packet(PEER, 8080, 1_000)),
            Outcome::Whitelisted
        );
        assert_eq!(e.tracker.len(), 0, "非保护端口不应产生展示记录");
    }

    #[test]
    fn 非法包长度不影响判定() {
        let mut e = engine();
        let mut pkt = syn_packet(PEER, 3389, 1_000);
        pkt.length = 0;
        assert!(matches!(e.evaluate(&pkt), Outcome::Tracking { .. }));
    }
}
