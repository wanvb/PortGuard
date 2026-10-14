//! 领域模型。
//!
//! 本模块只描述「数据长什么样」，不含任何 Windows API 依赖与副作用。

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// IP 统一以 `Ipv4Addr` 表达；进入规则判定前统一转 `u32` 比较，避免逐包字符串开销。
pub type Ip = Ipv4Addr;

/// 传输层协议。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

impl Protocol {
    /// 供 UI / 日志 / `netsh` 参数拼装使用的固定标识（不含任何用户输入）。
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
            Protocol::Icmp => "ICMP",
        }
    }
}

/// 流量方向（相对被监听网卡）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrafficDirection {
    /// 流入本机。
    Inbound,
    /// 流出本机。
    Outbound,
}

/// 保护策略分类。
///
/// 对应原程序的三套独立配置：TCP / TCP-WEB / UDP。
/// 「WEB」只是用户自行划分的另一组 TCP 端口，**不得硬编码 80/443**。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortGroup {
    /// 普通 TCP 保护端口。
    Tcp,
    /// TCP-WEB 保护端口（用户自定义归类）。
    Web,
    /// UDP 保护端口。
    Udp,
}

impl PortGroup {
    pub fn as_str(&self) -> &'static str {
        match self {
            PortGroup::Tcp => "TCP",
            PortGroup::Web => "TCP-WEB",
            PortGroup::Udp => "UDP",
        }
    }
}

/// TCP 标志位类别（观测用）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagClass {
    /// 纯 `SYN`：客户端连接请求。
    Syn,
    /// `SYN+ACK`：服务端握手响应。
    SynAck,
    /// `RST`：连接被拒绝或异常中断。
    Reset,
    /// `FIN`：挥手。
    Finish,
    /// 仅 `ACK`：数据或确认。
    Ack,
    /// 其它组合。
    Other,
}

impl FlagClass {
    pub fn label(&self) -> &'static str {
        match self {
            FlagClass::Syn => "SYN",
            FlagClass::SynAck => "SYN+ACK",
            FlagClass::Reset => "RST",
            FlagClass::Finish => "FIN",
            FlagClass::Ack => "ACK",
            FlagClass::Other => "其它",
        }
    }
}

/// TCP 标志位。不使用 bitflags 依赖，直接 6 个 bool，语义清晰且零成本。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
}

impl TcpFlags {
    /// 是否为「新建连接请求」。
    ///
    /// 规范 4.1：`SYN && !ACK` 才算连接请求；`SYN+ACK` 是服务端响应，不能计入客户端重连次数。
    pub fn is_connection_request(&self) -> bool {
        self.syn && !self.ack
    }

    /// 是否为「服务端已接受连接」的握手响应（`SYN && ACK`）。
    ///
    /// 只在把服务端应答当作连接事件来源时使用（见 `ProtectConfig::count_accept`）：
    /// 该信号由本机发出，不依赖混杂模式能否收到入站包。
    pub fn is_handshake_accepted(&self) -> bool {
        self.syn && self.ack
    }

    /// 标志位类别，用于观测统计（只关心与连接建立相关的几类）。
    pub fn class(&self) -> FlagClass {
        if self.syn && self.ack {
            FlagClass::SynAck
        } else if self.syn {
            FlagClass::Syn
        } else if self.rst {
            FlagClass::Reset
        } else if self.fin {
            FlagClass::Finish
        } else if self.ack {
            FlagClass::Ack
        } else {
            FlagClass::Other
        }
    }

    /// 是否携带 RST（连接被拒绝 / 异常中断）。
    pub fn is_reset(&self) -> bool {
        self.rst
    }

    /// 精简展示，用于日志与 UI。
    pub fn to_short_string(&self) -> String {
        let mut s = String::with_capacity(6);
        if self.syn {
            s.push('S');
        }
        if self.ack {
            s.push('A');
        }
        if self.fin {
            s.push('F');
        }
        if self.rst {
            s.push('R');
        }
        if self.psh {
            s.push('P');
        }
        if self.urg {
            s.push('U');
        }
        if s.is_empty() {
            s.push('-');
        }
        s
    }
}

/// 单个数据包的解析结果。抓包线程产出、规则引擎消费，是模块间唯一的数据契约。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketInfo {
    /// 源 IP。
    pub src: Ip,
    /// 目的 IP。
    pub dst: Ip,
    /// 源端口（ICMP 为 0）。
    pub src_port: u16,
    /// 目的端口（ICMP 为 0）。
    pub dst_port: u16,
    /// 协议。
    pub protocol: Protocol,
    /// TCP 标志位（非 TCP 时为默认全 false）。
    pub tcp_flags: TcpFlags,
    /// IP 层总长度。
    pub length: u16,
    /// 捕获时间（Unix 纪元毫秒）。
    pub timestamp_ms: u64,
}

impl PacketInfo {
    /// 判断该包相对本机地址的流向。
    pub fn direction(&self, local_ip: Ip) -> TrafficDirection {
        if self.src == local_ip {
            TrafficDirection::Outbound
        } else {
            TrafficDirection::Inbound
        }
    }

    /// 返回「对端 IP」：流入包取源、流出包取目的。
    pub fn peer_ip(&self, local_ip: Ip) -> Ip {
        match self.direction(local_ip) {
            TrafficDirection::Outbound => self.dst,
            TrafficDirection::Inbound => self.src,
        }
    }

    /// 返回「本机侧服务端口」：流入包取目的端口、流出包取源端口。
    pub fn service_port(&self, local_ip: Ip) -> u16 {
        match self.direction(local_ip) {
            TrafficDirection::Outbound => self.src_port,
            TrafficDirection::Inbound => self.dst_port,
        }
    }

    /// 返回「对端端口」。
    pub fn remote_port(&self, local_ip: Ip) -> u16 {
        match self.direction(local_ip) {
            TrafficDirection::Outbound => self.dst_port,
            TrafficDirection::Inbound => self.src_port,
        }
    }
}

/// 封停原因。原因必须进入日志与 UI 展示（规范 14）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BanReason {
    /// 命中黑名单。
    Blacklist,
    /// TCP 重连次数超阈值。
    TcpThreshold,
    /// TCP-WEB 重连次数超阈值。
    WebThreshold,
    /// UDP 报文次数超阈值。
    UdpThreshold,
    /// 用户在界面手动封停。
    Manual,
}

impl BanReason {
    /// 中文展示文案。
    pub fn label(&self) -> &'static str {
        match self {
            BanReason::Blacklist => "黑名单命中",
            BanReason::TcpThreshold => "TCP 重连超限",
            BanReason::WebThreshold => "WEB 重连超限",
            BanReason::UdpThreshold => "UDP 访问超限",
            BanReason::Manual => "手动封停",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            BanReason::Blacklist => "blacklist",
            BanReason::TcpThreshold => "tcp_threshold",
            BanReason::WebThreshold => "web_threshold",
            BanReason::UdpThreshold => "udp_threshold",
            BanReason::Manual => "manual",
        }
    }
}

/// 单条封停记录，同时是持久化单元。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BanRecord {
    /// 被封停的 IP。
    pub ip: Ip,
    /// 触发封停的协议（手动封停可为 `None`）。
    pub protocol: Option<Protocol>,
    /// 本机服务端口。
    pub service_port: Option<u16>,
    /// 对端端口。
    pub remote_port: Option<u16>,
    /// 触发时的累计次数。
    pub attempt_count: u32,
    /// 封停创建时间（Unix 纪元毫秒）。
    pub created_at_ms: u64,
    /// 到期时间；`None` 表示永久封停。
    pub expires_at_ms: Option<u64>,
    /// 是否永久封停。
    pub permanent: bool,
    /// 封停原因。
    pub reason: BanReason,
    /// 程序创建的防火墙规则名，用于精确解封，绝不误删他人规则。
    pub rule_name: String,
}

impl BanRecord {
    /// 判断在给定时刻是否已到期。
    pub fn is_expired_at(&self, now_ms: u64) -> bool {
        match self.expires_at_ms {
            Some(t) => now_ms >= t,
            None => false,
        }
    }

    /// 剩余秒数；永久封停返回 `None`。
    pub fn remaining_seconds(&self, now_ms: u64) -> Option<u64> {
        self.expires_at_ms.map(|t| t.saturating_sub(now_ms) / 1000)
    }
}

/// 被忽略数据包按原因分类的计数。
///
/// 只统计「抓到了、但没参与端口判定」的包，用于区分两类问题：
/// 抓包层收不到包，还是判定层把包丢掉了（规范 26.1：不得静默失效）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IgnoreCounters {
    /// 目的地址不是本机（混杂模式下网段内其它主机的流量）。
    pub not_local: u64,
    /// 本机主动外连（默认不计入阈值）。
    pub outbound: u64,
    /// 非新建连接（`SYN+ACK`、纯 `ACK`、`FIN` 等）。
    pub not_new_connection: u64,
    /// 服务端口不在任何保护组内。
    pub port_not_protected: u64,
    /// ICMP（只由系统级 Ping 屏蔽处理，不参与端口统计）。
    pub icmp: u64,
}

impl IgnoreCounters {
    /// 按面板展示顺序返回「中文标签 + 计数」。
    pub fn labeled(&self) -> [(&'static str, u64); 5] {
        [
            ("非本机流量", self.not_local),
            ("本机外连", self.outbound),
            ("非新建连接", self.not_new_connection),
            ("端口未保护", self.port_not_protected),
            ("ICMP", self.icmp),
        ]
    }
}

/// 运行统计快照，直接喂给 Web 面板的统计卡片。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statistics {
    /// 当前正在跟踪的 IP 数。
    pub tracking: u64,
    /// 当前已封停 IP 数（含永久）。
    pub banned: u64,
    /// 其中永久封停数。
    pub permanent: u64,
    /// 累计捕获包数。
    pub captured_packets: u64,
    /// 累计自动封停次数。
    pub total_bans: u64,
    /// 自进程启动以来的运行秒数。
    pub uptime_seconds: u64,
    /// 被忽略数据包的分类计数（排查「程序在跑、端口却没反应」）。
    pub ignored: IgnoreCounters,
}
