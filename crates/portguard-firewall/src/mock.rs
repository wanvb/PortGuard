//! 内存防火墙，用于单元测试与「无管理员权限」的演示模式。
//!
//! 规范 31：先完成业务测试，再进入真实防火墙集成测试。

use crate::backend::{is_our_rule, FirewallBackend, RuleDirection};
use portguard_core::error::Result;
use portguard_core::model::{Ip, Protocol};
use std::collections::HashSet;
use std::sync::Mutex;

/// 完全在内存中模拟防火墙行为。
#[derive(Debug, Default)]
pub struct MockFirewall {
    state: Mutex<MockState>,
}

#[derive(Debug, Default)]
struct MockState {
    enabled: bool,
    /// 已创建的规则名集合。
    rules: HashSet<String>,
    /// 规则名 → 封停的 IP，用于断言 remoteip 参数是否正确。
    blocked_ips: Vec<(String, Ip)>,
    /// 记录调用顺序，便于断言「先删后加」等幂等行为。
    calls: Vec<String>,
}

impl MockFirewall {
    /// 构造一个默认启用、无任何规则的模拟防火墙。
    pub fn new() -> Self {
        MockFirewall {
            state: Mutex::new(MockState {
                enabled: true,
                ..Default::default()
            }),
        }
    }

    /// 当前被封锁的 IP 列表（测试断言用）。
    pub fn blocked_ips(&self) -> Vec<Ip> {
        self.state
            .lock()
            .map(|s| s.blocked_ips.iter().map(|(_, ip)| *ip).collect())
            .unwrap_or_default()
    }

    /// 当前规则名列表。
    pub fn rule_names(&self) -> Vec<String> {
        self.state
            .lock()
            .map(|s| {
                let mut v: Vec<String> = s.rules.iter().cloned().collect();
                v.sort();
                v
            })
            .unwrap_or_default()
    }

    /// 调用轨迹（测试断言用）。
    pub fn calls(&self) -> Vec<String> {
        self.state
            .lock()
            .map(|s| s.calls.clone())
            .unwrap_or_default()
    }

    fn with<F: FnOnce(&mut MockState) -> Result<()>>(&self, f: F) -> Result<()> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| portguard_core::AppError::Firewall("Mock 状态锁被污染".into()))?;
        f(&mut guard)
    }
}

impl FirewallBackend for MockFirewall {
    fn name(&self) -> &'static str {
        "MockFirewall"
    }

    fn is_enabled(&self) -> Result<bool> {
        Ok(self.state.lock().map(|s| s.enabled).unwrap_or(false))
    }

    fn block_ip(&self, ip: Ip, rule_name: &str) -> Result<()> {
        self.with(|s| {
            s.calls.push(format!("block_ip:{}:{}", ip, rule_name));
            // 幂等：先清理同名规则再添加。
            s.rules.remove(rule_name);
            s.blocked_ips.retain(|(n, _)| n != rule_name);
            s.rules.insert(rule_name.to_string());
            s.blocked_ips.push((rule_name.to_string(), ip));
            Ok(())
        })
    }

    fn delete_rule(&self, rule_name: &str) -> Result<()> {
        self.with(|s| {
            s.calls.push(format!("delete_rule:{}", rule_name));
            // 严格只删自己创建的规则，防止误删系统规则。
            if !is_our_rule(rule_name) {
                return Err(portguard_core::AppError::Firewall(format!(
                    "拒绝删除非本程序规则：{}",
                    rule_name
                )));
            }
            s.rules.remove(rule_name);
            s.blocked_ips.retain(|(n, _)| n != rule_name);
            Ok(())
        })
    }

    fn rule_exists(&self, rule_name: &str) -> Result<bool> {
        Ok(self
            .state
            .lock()
            .map(|s| s.rules.contains(rule_name))
            .unwrap_or(false))
    }

    fn list_own_rules(&self) -> Result<Vec<String>> {
        Ok(self
            .state
            .lock()
            .map(|s| {
                let mut v: Vec<String> = s
                    .rules
                    .iter()
                    .filter(|n| is_our_rule(n))
                    .cloned()
                    .collect();
                v.sort();
                v
            })
            .unwrap_or_default())
    }

    fn block_ports(
        &self,
        proto: Protocol,
        ports: &[u16],
        rule_name: &str,
        direction: RuleDirection,
    ) -> Result<()> {
        self.with(|s| {
            s.calls.push(format!(
                "block_ports:{}:{}:{}:{}",
                proto.as_str(),
                rule_name,
                direction.as_netsh(),
                ports.len()
            ));
            s.rules.insert(rule_name.to_string());
            Ok(())
        })
    }

    fn set_block_icmp(&self, v4: bool, v6: bool) -> Result<()> {
        self.with(|s| {
            s.calls.push(format!("set_block_icmp:{}:{}", v4, v6));
            for (flag, name) in [
                (v4, crate::backend::RULE_ICMP_V4),
                (v6, crate::backend::RULE_ICMP_V6),
            ] {
                if flag {
                    s.rules.insert(name.to_string());
                } else {
                    s.rules.remove(name);
                }
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ip {
        s.parse().unwrap()
    }

    #[test]
    fn 封停与删除规则幂等() {
        let fw = MockFirewall::new();
        fw.block_ip(ip("1.2.3.4"), "PortGuard-Ban-1.2.3.4").unwrap();
        fw.block_ip(ip("1.2.3.4"), "PortGuard-Ban-1.2.3.4").unwrap();
        assert_eq!(fw.rule_names().len(), 1);
        assert_eq!(fw.blocked_ips(), vec![ip("1.2.3.4")]);
        fw.delete_rule("PortGuard-Ban-1.2.3.4").unwrap();
        assert!(fw.rule_names().is_empty());
        assert!(fw.blocked_ips().is_empty());
    }

    #[test]
    fn 拒绝删除非本程序规则() {
        let fw = MockFirewall::new();
        let r = fw.delete_rule("远程桌面 (TCP-In)");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("拒绝删除"));
    }

    #[test]
    fn 列表只返回本程序规则() {
        let fw = MockFirewall::new();
        fw.block_ip(ip("1.1.1.1"), "PortGuard-Ban-1.1.1.1").unwrap();
        fw.block_ports(Protocol::Tcp, &[445], crate::backend::RULE_RISKY_TCP, RuleDirection::In)
            .unwrap();
        let own = fw.list_own_rules().unwrap();
        assert!(own.contains(&"PortGuard-Ban-1.1.1.1".to_string()));
        assert!(own.contains(&crate::backend::RULE_RISKY_TCP.to_string()));
    }

    #[test]
    fn 网际控制报文屏蔽可开可关() {
        let fw = MockFirewall::new();
        fw.set_block_icmp(true, true).unwrap();
        assert_eq!(fw.rule_names().len(), 2);
        fw.set_block_icmp(false, false).unwrap();
        assert!(fw.rule_names().is_empty());
    }

    #[test]
    fn 规则存在性查询() {
        let fw = MockFirewall::new();
        assert!(!fw.rule_exists("PortGuard-Ban-9.9.9.9").unwrap());
        fw.block_ip(ip("9.9.9.9"), "PortGuard-Ban-9.9.9.9").unwrap();
        assert!(fw.rule_exists("PortGuard-Ban-9.9.9.9").unwrap());
    }
}
