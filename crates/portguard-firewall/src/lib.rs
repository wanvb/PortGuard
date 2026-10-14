//! Windows 防火墙适配层。
//!
//! 对外只暴露 [`backend::FirewallBackend`] 这一层抽象：
//!
//! - [`mock::MockFirewall`]：纯内存实现，用于单元测试与无管理员权限的演示；
//! - [`netsh::NetshFirewall`]：真实后端，基于 `netsh advfirewall`。

pub mod backend;
pub mod mock;
#[cfg(windows)]
pub mod netsh;

pub use backend::{FirewallBackend, RuleDirection};
pub use mock::MockFirewall;
#[cfg(windows)]
pub use netsh::NetshFirewall;

use portguard_core::ban::is_own_rule;
use portguard_core::error::Result;
use std::sync::Arc;

/// 创建默认后端：Windows 上使用 netsh，其他平台自动退回 Mock，
/// 保证 `cargo test` 在任何平台都能跑（规范 30 可测试性优先）。
pub fn default_backend() -> Arc<dyn FirewallBackend> {
    #[cfg(windows)]
    {
        Arc::new(NetshFirewall::new())
    }
    #[cfg(not(windows))]
    {
        Arc::new(MockFirewall::new())
    }
}

/// 清理启动前残留的孤儿规则。
///
/// 只处理 `PortGuard-Ban-` 前缀、且当前封停列表里不存在的规则，
/// 绝不触碰系统或第三方规则（规范 8.4 / 26.3）。
pub fn cleanup_orphans(
    backend: &dyn FirewallBackend,
    active_rule_names: &[String],
) -> Result<Vec<String>> {
    let own = backend.list_own_rules()?;
    let mut removed = Vec::new();
    for name in own {
        if !is_own_rule(&name) {
            continue;
        }
        if active_rule_names.iter().any(|a| a == &name) {
            continue;
        }
        if backend.delete_rule(&name).is_ok() {
            removed.push(name);
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 清理孤儿规则不会误删在用规则() {
        let fw = MockFirewall::new();
        fw.block_ip("1.1.1.1".parse().unwrap(), "PortGuard-Ban-1.1.1.1")
            .unwrap();
        fw.block_ip("2.2.2.2".parse().unwrap(), "PortGuard-Ban-2.2.2.2")
            .unwrap();
        let removed =
            cleanup_orphans(&fw, &["PortGuard-Ban-1.1.1.1".to_string()]).unwrap();
        assert_eq!(removed, vec!["PortGuard-Ban-2.2.2.2".to_string()]);
        assert!(fw.rule_exists("PortGuard-Ban-1.1.1.1").unwrap());
    }
}
