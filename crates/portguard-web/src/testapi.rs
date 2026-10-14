//! 仅测试用的 `PortGuardApi` 实现。
//!
//! 用途：让路由与 HTTP 服务能在没有真实抓包 / 防火墙 / 管理员权限的
//! 环境下跑完整链路测试（包括跨进程的真实 socket 往返）。
//!
//! 行为刻意做得「像真的」：白名单里的 IP 拒绝封停、封停后从跟踪列表消失、
//! 保存配置时做校验——这样测试才能真正覆盖到错误分支。

use portguard_core::api::{
    AdapterView, BanView, ConnectionView, EventView, ObservedPortView, PortGuardApi,
    ProtectionSwitch, StatusView,
};
use portguard_core::config::Config;
use portguard_core::error::{AppError, Result};
use portguard_core::logging::{Level, LogLine};
use portguard_core::model::{IgnoreCounters, Ip, Statistics};
use std::sync::Mutex;

/// 内存状态。
pub struct MockState {
    pub running: bool,
    pub config: Config,
    pub bans: Vec<BanView>,
    pub connections: Vec<ConnectionView>,
    pub logs: Vec<LogLine>,
    pub events: Vec<EventView>,
    pub adapters: Vec<AdapterView>,
    pub captured: u64,
}

/// 测试用 API。
pub struct MockApi {
    state: Mutex<MockState>,
}

impl Default for MockApi {
    fn default() -> Self {
        MockApi::new()
    }
}

impl MockApi {
    pub fn new() -> MockApi {
        let mut config = Config::with_defaults();
        config.lists.whitelist = vec!["10.0.0.1".to_string()];
        config.network.adapter = "192.168.1.100".to_string();

        MockApi {
            state: Mutex::new(MockState {
                running: true,
                config,
                bans: vec![BanView {
                    ip: "203.0.113.9".to_string(),
                    reason: "tcp_threshold".to_string(),
                    reason_label: "TCP 阈值触发".to_string(),
                    protocol: "TCP".to_string(),
                    service_port: Some(3389),
                    remote_port: Some(51000),
                    attempt_count: 7,
                    created_at_ms: 1_700_000_000_000,
                    expires_at_ms: Some(1_700_003_600_000),
                    permanent: false,
                    remaining_seconds: Some(1200),
                    rule_name: "PortGuard-Ban-203.0.113.9".to_string(),
                    location: "中国 · 北京市 · 北京市 · 联通".to_string(),
                }],
                connections: vec![ConnectionView {
                    ip: "198.51.100.7".to_string(),
                    group: "TCP".to_string(),
                    service_port: 3389,
                    count: 3,
                    first_seen_ms: 1_700_000_000_000,
                    last_seen_ms: 1_700_000_005_000,
                    threshold: 5,
                    state: "TRACKING".to_string(),
                    whitelisted: false,
                    location: "中国 · 福建省 · 福州市 · 中国电信".to_string(),
                }],
                logs: vec![LogLine {
                    ts_ms: 1_700_000_000_000,
                    level: Level::Info,
                    message: "抓包已启动".to_string(),
                }],
                events: vec![EventView {
                    ts_ms: 1_700_000_000_000,
                    kind: "ban".to_string(),
                    message: "203.0.113.9 因 TCP 阈值被封停".to_string(),
                    ip: Some("203.0.113.9".to_string()),
                }],
                adapters: vec![AdapterView {
                    ip: "192.168.1.100".to_string(),
                    mask: "255.255.255.0".to_string(),
                    description: "Intel(R) Ethernet Connection".to_string(),
                    is_virtual: false,
                    selected: true,
                    usable: true,
                }],
                captured: 12345,
            }),
        }
    }

    /// 测试断言辅助：读取当前状态。
    pub fn peek<T>(&self, f: impl FnOnce(&MockState) -> T) -> T {
        let s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        f(&s)
    }

    fn mutate<T>(&self, f: impl FnOnce(&mut MockState) -> T) -> T {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut s)
    }

    fn push_event(state: &mut MockState, kind: &str, message: String, ip: Option<String>) {
        state.events.insert(
            0,
            EventView {
                ts_ms: 1_700_000_100_000,
                kind: kind.to_string(),
                message,
                ip,
            },
        );
    }

    /// 模拟「封停」的完整效果（含白名单硬校验）。
    fn do_ban(state: &mut MockState, ip: Ip, permanent: bool) -> Result<()> {
        if state
            .config
            .lists
            .whitelist
            .iter()
            .any(|r| r == &ip.to_string())
        {
            return Err(AppError::Other(format!("{} 在白名单中，拒绝封停", ip)));
        }
        let text = ip.to_string();
        if !state.bans.iter().any(|b| b.ip == text) {
            state.bans.push(BanView {
                ip: text.clone(),
                reason: "manual".to_string(),
                reason_label: "手动封停".to_string(),
                protocol: "-".to_string(),
                service_port: None,
                remote_port: None,
                attempt_count: 0,
                created_at_ms: 1_700_000_200_000,
                expires_at_ms: if permanent { None } else { Some(1_700_003_600_000) },
                permanent,
                remaining_seconds: if permanent { None } else { Some(3600) },
                rule_name: format!("PortGuard-Ban-{}", text),
                location: "保留地址".to_string(),
            });
        }
        state.connections.retain(|c| c.ip != text);
        MockApi::push_event(state, "ban", format!("{} 已被封停", text), Some(text));
        Ok(())
    }
}

impl PortGuardApi for MockApi {
    fn status(&self) -> StatusView {
        self.peek(|s| {
            let banned = s.bans.len() as u64;
            let permanent = s.bans.iter().filter(|b| b.permanent).count() as u64;
            StatusView {
                running: s.running,
                adapter: s.config.network.adapter.clone(),
                local_ip: s.config.network.adapter.clone(),
                panel_bind: s.config.panel.bind.clone(),
                admin: true,
                capture_ready: s.running,
                stats: Statistics {
                    tracking: s.connections.len() as u64,
                    banned,
                    permanent,
                    captured_packets: s.captured,
                    total_bans: banned,
                    uptime_seconds: 42,
                    // 桩接口给一组非零计数，保证面板的判定明细区在端到端测试里也被渲染
                    ignored: IgnoreCounters {
                        not_local: 7,
                        outbound: 3,
                        not_new_connection: 5,
                        port_not_protected: 11,
                        icmp: 2,
                    },
                },
                started_at_ms: 1_700_000_000_000,
                version: "test".to_string(),
                protected_ports: s.config.protect.tcp.ports.len()
                    + s.config.protect.udp.ports.len()
                    + s.config.protect.http.ports.len(),
                risky_ports: s.config.system.risky_ports,
                block_icmp: s.config.system.block_icmp,
                autostart: s.config.system.autostart,
                rdp_enabled: s.config.rdp.enabled,
                geo_ready: true,
                geo_status: "test/ip2region_v4.xdb".to_string(),
                // 桩接口给一组非零诊断数据，保证面板的观测区在端到端测试里也被渲染
                parse_errors: 4,
                parse_samples: vec!["60 字节：45 00 00 3C 00 00 00 00（IPv4 分片暂不支持）".to_string()],
                observed: vec![
                    ObservedPortView {
                        direction: "入站".to_string(),
                        protocol: "TCP".to_string(),
                        port: 3389,
                        flags: "SYN".to_string(),
                        count: 9,
                    },
                    ObservedPortView {
                        direction: "出站".to_string(),
                        protocol: "TCP".to_string(),
                        port: 3389,
                        flags: "SYN+ACK".to_string(),
                        count: 5,
                    },
                ],
                count_accept: false,
            }
        })
    }

    fn connections(&self) -> Vec<ConnectionView> {
        self.peek(|s| s.connections.clone())
    }

    fn bans(&self) -> Vec<BanView> {
        self.peek(|s| s.bans.clone())
    }

    fn config(&self) -> Config {
        self.peek(|s| s.config.clone())
    }

    fn save_config(&self, cfg: Config) -> Result<Config> {
        let errs = cfg.validate();
        if !errs.is_empty() {
            return Err(AppError::Config(errs.join("；")));
        }
        Ok(self.mutate(|s| {
            s.config = cfg.clone();
            s.config.normalize();
            s.config.clone()
        }))
    }

    fn start(&self) -> Result<()> {
        self.mutate(|s| {
            s.running = true;
            MockApi::push_event(s, "system", "保护已启动".to_string(), None);
        });
        Ok(())
    }

    fn stop(&self) -> Result<()> {
        self.mutate(|s| {
            s.running = false;
        });
        Ok(())
    }

    fn ban_ip(&self, ip: Ip, permanent: bool) -> Result<()> {
        self.mutate(|s| MockApi::do_ban(s, ip, permanent))
    }

    fn unban_ip(&self, ip: Ip) -> Result<()> {
        self.mutate(|s| {
            let text = ip.to_string();
            s.bans.retain(|b| b.ip != text);
            MockApi::push_event(s, "unban", format!("{} 已解封", text), Some(text));
            Ok(())
        })
    }

    fn whitelist_add(&self, rule: &str) -> Result<()> {
        let rule = rule.trim().to_string();
        // 借真实解析器校验规则合法性
        portguard_core::iprange::IpSet::from_rules(std::slice::from_ref(&rule))?;
        self.mutate(|s| {
            if !s.config.lists.whitelist.contains(&rule) {
                s.config.lists.whitelist.push(rule.clone());
            }
            // 白名单优先：加入后立即解封
            s.bans.retain(|b| b.ip != rule);
            MockApi::push_event(s, "system", format!("{} 已加入白名单", rule), Some(rule));
            Ok(())
        })
    }

    fn blacklist_add(&self, rule: &str) -> Result<()> {
        let rule = rule.trim().to_string();
        portguard_core::iprange::IpSet::from_rules(std::slice::from_ref(&rule))?;
        self.mutate(|s| {
            if !s.config.lists.blacklist.contains(&rule) {
                s.config.lists.blacklist.push(rule.clone());
            }
            MockApi::push_event(s, "system", format!("{} 已加入黑名单", rule), None);
            Ok(())
        })
    }

    fn whitelist_remove(&self, rule: &str) -> Result<()> {
        self.mutate(|s| {
            s.config.lists.whitelist.retain(|r| r != rule);
            Ok(())
        })
    }

    fn blacklist_remove(&self, rule: &str) -> Result<()> {
        self.mutate(|s| {
            s.config.lists.blacklist.retain(|r| r != rule);
            Ok(())
        })
    }

    fn logs(&self, limit: usize) -> Vec<LogLine> {
        self.peek(|s| {
            let n = limit.min(s.logs.len());
            s.logs[s.logs.len() - n..].to_vec()
        })
    }

    fn events(&self, limit: usize) -> Vec<EventView> {
        self.peek(|s| {
            let n = limit.min(s.events.len());
            s.events[..n].to_vec()
        })
    }

    fn adapters(&self) -> Vec<AdapterView> {
        self.peek(|s| s.adapters.clone())
    }

    fn select_adapter(&self, ip: &str) -> Result<()> {
        if portguard_core::iprange::parse_ipv4(ip).is_err() {
            return Err(AppError::InvalidIpRule(format!("网卡地址非法：{}", ip)));
        }
        self.mutate(|s| {
            s.config.network.adapter = ip.to_string();
            for a in s.adapters.iter_mut() {
                a.selected = a.ip == ip;
            }
        });
        Ok(())
    }

    fn set_protection(&self, key: ProtectionSwitch, enabled: bool) -> Result<()> {
        self.mutate(|s| {
            match key {
                ProtectionSwitch::RiskyPorts => s.config.system.risky_ports = enabled,
                ProtectionSwitch::BlockIcmp => s.config.system.block_icmp = enabled,
                ProtectionSwitch::Autostart => s.config.system.autostart = enabled,
                ProtectionSwitch::RdpGuard => s.config.rdp.enabled = enabled,
            }
            MockApi::push_event(
                s,
                "system",
                format!("保护开关 {:?} 已设为 {}", key, enabled),
                None,
            );
        });
        Ok(())
    }

    fn data_dir(&self) -> String {
        "D:/PortGuard/data".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 白名单地址无法被封停() {
        let api = MockApi::new();
        assert!(api.ban_ip("10.0.0.1".parse().unwrap(), true).is_err());
        // 初始那条封停记录还在，但绝不能新增被白名单保护的地址
        assert_eq!(api.bans().len(), 1);
        assert!(api.bans().iter().all(|b| b.ip != "10.0.0.1"));
    }

    #[test]
    fn 封停后从跟踪列表移除() {
        let api = MockApi::new();
        api.ban_ip("198.51.100.7".parse().unwrap(), true).unwrap();
        assert!(api.connections().is_empty());
        assert_eq!(api.bans().len(), 2);
    }

    #[test]
    fn 加入白名单会立即解封() {
        let api = MockApi::new();
        api.whitelist_add("203.0.113.9").unwrap();
        assert!(api.bans().is_empty(), "白名单优先级最高，必须立即解封");
    }

    #[test]
    fn 非法名单规则被拒绝() {
        let api = MockApi::new();
        assert!(api.whitelist_add("不是IP").is_err());
        assert!(api.blacklist_add("1.2.3.4.5").is_err());
    }

    #[test]
    fn 保存非法配置被拒绝() {
        let api = MockApi::new();
        let mut cfg = api.config();
        cfg.lists.whitelist = vec!["坏规则".to_string()];
        assert!(api.save_config(cfg).is_err());
    }

    #[test]
    fn 状态统计与实际数据一致() {
        let api = MockApi::new();
        let st = api.status();
        assert_eq!(st.stats.banned, api.bans().len() as u64);
        assert_eq!(st.stats.tracking, api.connections().len() as u64);
        assert_eq!(st.protected_ports, 4, "默认 3389 + 3389 + 80 + 443");
    }

    #[test]
    fn 非法网卡地址被拒绝() {
        let api = MockApi::new();
        assert!(api.select_adapter("999.1.1.1").is_err());
        assert!(api.select_adapter("10.0.0.5").is_ok());
        assert_eq!(api.status().adapter, "10.0.0.5");
    }
}
