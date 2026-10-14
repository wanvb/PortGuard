//! 防火墙后端抽象。
//!
//! 规范 8.1：所有防火墙操作必须集中在本 crate，UI 与核心业务
//! 一律不得出现 `Command::new("netsh")`。

use portguard_core::error::Result;
use portguard_core::model::{Ip, Protocol};

/// 危险端口保护规则名（与规范 9 保持一致，写死常量，不拼接用户输入）。
pub const RULE_RISKY_TCP: &str = "PortGuard-Protect-RiskyPorts-TCP";
/// 危险端口保护 UDP 规则名。
pub const RULE_RISKY_UDP: &str = "PortGuard-Protect-RiskyPorts-UDP";
/// ICMPv4 屏蔽规则名。
pub const RULE_ICMP_V4: &str = "PortGuard-Block-ICMPv4";
/// ICMPv6 屏蔽规则名。
pub const RULE_ICMP_V6: &str = "PortGuard-Block-ICMPv6";

/// 本程序创建的**非封停类**规则名清单，用于清理与自检。
pub const OWN_SYSTEM_RULES: &[&str] = &[RULE_RISKY_TCP, RULE_RISKY_UDP, RULE_ICMP_V4, RULE_ICMP_V6];

/// 「危险端口保护」覆盖的端口：Windows 文件共享与旧式 NetBIOS 相关服务，
/// 长期是勒索软件横向移动的首选入口。
pub const RISKY_PORTS: &[u16] = &[135, 137, 138, 139, 445];

/// 本程序所有防火墙规则的统一前缀。
///
/// 比 `portguard_core::ban::RULE_PREFIX` 更宽：后者只标识封停规则，
/// 本前缀同时覆盖危险端口、ICMP 屏蔽等系统级规则。
pub const OWN_PREFIX: &str = "PortGuard-";

/// 判断规则名是否由本程序创建（宽口径，覆盖全部规则类型）。
///
/// 这是删除规则的唯一准入条件——绝不允许按 `remoteip` 等条件去删规则，
/// 否则可能误删系统或第三方规则（规范 8.4）。
#[inline]
pub fn is_our_rule(name: &str) -> bool {
    name.starts_with(OWN_PREFIX)
}

/// 规则方向。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleDirection {
    In,
    Out,
}

impl RuleDirection {
    pub fn as_netsh(&self) -> &'static str {
        match self {
            RuleDirection::In => "in",
            RuleDirection::Out => "out",
        }
    }
}

/// 防火墙操作结果。
///
/// 规范 26.1（Fail safe）：操作失败必须如实上报，
/// 绝不返回「假装成功」，否则内部状态会与系统实际状态漂移。
pub trait FirewallBackend: Send + Sync {
    /// 后端名称，用于日志与面板展示。
    fn name(&self) -> &'static str;

    /// 防火墙是否处于启用状态（仅用于展示，不参与判定）。
    fn is_enabled(&self) -> Result<bool>;

    /// 封停一个 IP。实现必须幂等。
    fn block_ip(&self, ip: Ip, rule_name: &str) -> Result<()>;

    /// 按规则名精确删除规则。实现必须保证只删本程序创建的规则。
    fn delete_rule(&self, rule_name: &str) -> Result<()>;

    /// 规则是否已存在。
    fn rule_exists(&self, rule_name: &str) -> Result<bool>;

    /// 列出所有由本程序创建的规则名（用于启动自检与清理孤儿规则）。
    fn list_own_rules(&self) -> Result<Vec<String>>;

    /// 添加一条端口封锁规则（危险端口保护）。
    fn block_ports(
        &self,
        proto: Protocol,
        ports: &[u16],
        rule_name: &str,
        direction: RuleDirection,
    ) -> Result<()>;

    /// 屏蔽 / 恢复 ICMP Echo Request。
    fn set_block_icmp(&self, v4: bool, v6: bool) -> Result<()>;
}

/// 不带 UI 的进程调用封装占位，避免各后端重复实现。
pub(crate) fn ports_to_netsh(ports: &[u16]) -> String {
    ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",")
}
