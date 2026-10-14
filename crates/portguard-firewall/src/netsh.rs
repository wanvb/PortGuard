//! `netsh advfirewall` 后端。
//!
//! 选型说明（对齐规范 8.2）：首选方案是 `INetFwPolicy2` COM API，
//! 但 COM 实现代码量大、调试成本高。规范同时允许 `netsh advfirewall` 作为
//! 兼容性后端，因此第一阶段先落地 netsh 后端，并保证：
//!
//! 1. **绝不经过 shell**：使用 `Command::new("netsh").args([...])`，
//!    参数以数组传递，不存在命令注入面；
//! 2. **所有参数都经过强类型转换**：IP 由 `Ipv4Addr` 格式化、端口由 `u16`
//!    格式化、规则名由常量前缀 + IP 生成，用户输入永远不进入命令行；
//! 3. **检查退出码与 stderr**，失败如实返回 `AppError::Firewall`；
//! 4. **删除前校验归属**：只允许删除 `PortGuard-` 前缀的规则（规范 8.4）。

use crate::backend::{is_our_rule, FirewallBackend, RuleDirection};
use portguard_core::error::{AppError, Result};
use portguard_core::model::{Ip, Protocol};

/// `CREATE_NO_WINDOW`：避免每次调用 netsh 都弹出控制台窗口。
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// 基于 `netsh advfirewall` 的真实防火墙后端。
#[derive(Debug, Default)]
pub struct NetshFirewall;

impl NetshFirewall {
    pub fn new() -> Self {
        NetshFirewall
    }

    /// 执行 netsh 并返回 stdout。
    fn run(args: &[&str]) -> Result<String> {
        use std::os::windows::process::CommandExt;
        use std::process::Command;

        let output = Command::new("netsh")
            .args(args)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| AppError::Firewall(format!("无法执行 netsh：{}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if output.status.success() {
            Ok(stdout)
        } else {
            let code = output.status.code().unwrap_or(-1);
            // netsh 的失败信息主要走 stdout，stderr 常常为空，两者都要带上。
            let detail = format!(
                "netsh {} 失败（退出码 {}）：{} {}",
                args.join(" "),
                code,
                stdout.trim(),
                stderr.trim()
            );
            Err(AppError::Firewall(detail.trim_end().to_string()))
        }
    }

    /// 执行 netsh 并返回 (是否成功, 输出)。
    ///
    /// 用于「允许失败」的场景（例如删除一条本就不存在的规则）。
    fn run_tolerant(args: &[&str]) -> (bool, String) {
        match Self::run(args) {
            Ok(out) => (true, out),
            Err(e) => (false, e.to_string()),
        }
    }
}

impl FirewallBackend for NetshFirewall {
    fn name(&self) -> &'static str {
        "netsh advfirewall"
    }

    fn is_enabled(&self) -> Result<bool> {
        let out = Self::run(&["advfirewall", "show", "allprofiles", "state"])?;
        // 输出随系统语言变化：英文 ON/OFF、中文 启用/关闭。
        // 这里只做展示用途，判定「任一配置文件为启用即视为开启」。
        let has_on = out.contains("ON") || out.contains("启用");
        let has_off = out.contains("OFF") || out.contains("关闭");
        Ok(has_on || !has_off)
    }

    fn block_ip(&self, ip: Ip, rule_name: &str) -> Result<()> {
        if !is_our_rule(rule_name) {
            return Err(AppError::Firewall(format!(
                "拒绝创建非本程序前缀的规则：{}",
                rule_name
            )));
        }
        // 幂等：先删同名规则，避免 netsh 因重名拒绝添加。
        let _ = Self::run_tolerant(&[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={}", rule_name),
        ]);

        let remote = format!("remoteip={}", ip);
        let name = format!("name={}", rule_name);
        Self::run(&[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &name,
            "dir=in",
            "action=block",
            &remote,
            "protocol=any",
            "enable=yes",
            "profile=any",
        ])?;

        // 验证规则确实落地，避免「netsh 退出码为 0 但规则没生效」的静默失败。
        if !self.rule_exists(rule_name)? {
            return Err(AppError::Firewall(format!(
                "规则 {} 创建后查询不到，防火墙可能被组策略接管",
                rule_name
            )));
        }
        Ok(())
    }

    fn delete_rule(&self, rule_name: &str) -> Result<()> {
        if !is_our_rule(rule_name) {
            return Err(AppError::Firewall(format!(
                "拒绝删除非本程序规则：{}",
                rule_name
            )));
        }
        let name = format!("name={}", rule_name);
        // 规则不存在时 netsh 会返回失败，这里视为成功（解封幂等）。
        let (ok, msg) = Self::run_tolerant(&[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &name,
        ]);
        if ok || !self.rule_exists(rule_name).unwrap_or(false) {
            Ok(())
        } else {
            Err(AppError::Firewall(msg))
        }
    }

    fn rule_exists(&self, rule_name: &str) -> Result<bool> {
        let name = format!("name={}", rule_name);
        let (ok, _) =
            Self::run_tolerant(&["advfirewall", "firewall", "show", "rule", &name]);
        // 规则不存在时 netsh 以非 0 退出码结束，因此直接用退出码判断，
        // 完全不受系统语言影响（规范 29 兼容性红线）。
        Ok(ok)
    }

    fn list_own_rules(&self) -> Result<Vec<String>> {
        let out = Self::run(&["advfirewall", "firewall", "show", "rule", "name=all"])?;
        let mut names = Vec::new();
        for line in out.lines() {
            // 同时兼容半角与全角冒号，不依赖「规则名称」这四个字的中文写法。
            let value = match line.split_once(':').map(|(_, v)| v) {
                Some(v) => v,
                None => match line.split_once('：').map(|(_, v)| v) {
                    Some(v) => v,
                    None => continue,
                },
            };
            let value = value.trim();
            if is_our_rule(value) {
                names.push(value.to_string());
            }
        }
        names.sort();
        names.dedup();
        Ok(names)
    }

    fn block_ports(
        &self,
        proto: Protocol,
        ports: &[u16],
        rule_name: &str,
        direction: RuleDirection,
    ) -> Result<()> {
        if !is_our_rule(rule_name) {
            return Err(AppError::Firewall(format!(
                "拒绝创建非本程序前缀的规则：{}",
                rule_name
            )));
        }
        if ports.is_empty() {
            return Err(AppError::Firewall("端口列表为空，拒绝创建规则".into()));
        }
        let _ = Self::run_tolerant(&[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={}", rule_name),
        ]);

        let proto_arg = match proto {
            Protocol::Tcp => "protocol=tcp",
            Protocol::Udp => "protocol=udp",
            // 端口规则只对 TCP/UDP 有意义；ICMP 走 set_block_icmp。
            Protocol::Icmp => return Err(AppError::Firewall("ICMP 不支持端口规则".into())),
        };
        Self::run(&[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={}", rule_name),
            &format!("dir={}", direction.as_netsh()),
            "action=block",
            proto_arg,
            &format!("localport={}", crate::backend::ports_to_netsh(ports)),
            "enable=yes",
            "profile=any",
        ])?;
        Ok(())
    }

    fn set_block_icmp(&self, v4: bool, v6: bool) -> Result<()> {
        for (enabled, name, proto) in [
            (v4, crate::backend::RULE_ICMP_V4, "protocol=icmpv4:8,any"),
            (v6, crate::backend::RULE_ICMP_V6, "protocol=icmpv6:128,any"),
        ] {
            let _ = Self::run_tolerant(&[
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={}", name),
            ]);
            if enabled {
                Self::run(&[
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &format!("name={}", name),
                    "dir=in",
                    "action=block",
                    proto,
                    "remoteip=any",
                    "enable=yes",
                    "profile=any",
                ])?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portguard_core::ban::{ban_rule_name, is_own_rule};

    fn ip(s: &str) -> Ip {
        s.parse().unwrap()
    }

    #[test]
    fn 规则名必须带本程序前缀才允许创建() {
        let fw = NetshFirewall::new();
        // 只验证前置校验，不会真的调用 netsh（前缀不合法直接返回错误）。
        let r = fw.block_ports(Protocol::Tcp, &[445], "别人的规则", RuleDirection::In);
        assert!(r.is_err());
        let r2 = fw.block_ip(ip("1.2.3.4"), "Evil-Rule");
        assert!(r2.is_err());
    }

    #[test]
    fn 空端口列表被拒绝() {
        let fw = NetshFirewall::new();
        let r = fw.block_ports(Protocol::Tcp, &[], "PortGuard-Protect-Test", RuleDirection::In);
        assert!(r.is_err());
    }

    #[test]
    fn 网际控制报文不支持端口规则() {
        let fw = NetshFirewall::new();
        let r = fw.block_ports(
            Protocol::Icmp,
            &[1],
            "PortGuard-Protect-Test",
            RuleDirection::In,
        );
        assert!(r.is_err());
    }

    #[test]
    fn 封停规则名生成稳定() {
        assert_eq!(ban_rule_name(ip("1.2.3.4")), "PortGuard-Ban-1.2.3.4");
        assert!(is_own_rule(&ban_rule_name(ip("255.255.255.255"))));
    }
}
