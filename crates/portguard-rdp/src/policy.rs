//! RDP 接入策略（纯逻辑，便于单元测试）。
//!
//! 策略意图（对齐旧版「远程桌面客户端计算机名白名单」）：
//! 只有来自受信计算机的远程桌面连接才允许建立，其余一律断开。
//!
//! 三条硬约束：
//! 1. **本地控制台会话永不处理**——它没有客户端名，断开它等于把管理员锁在门外；
//! 2. **白名单为空 = 不限制**——避免一次误配置把整台服务器锁死；
//! 3. **本程序所在会话永不处理**——否则会把自己踢下线。

use portguard_core::config::RdpConfig;
use portguard_core::error::{AppError, Result};

use crate::session::{self, SessionInfo};

/// 对单个会话的判定结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RdpDecision {
    /// 放行。
    Allow(&'static str),
    /// 断开，附带中文原因。
    Block(&'static str),
}

impl RdpDecision {
    pub fn is_block(&self) -> bool {
        matches!(self, RdpDecision::Block(_))
    }

    pub fn reason(&self) -> &'static str {
        match self {
            RdpDecision::Allow(r) | RdpDecision::Block(r) => r,
        }
    }
}

/// 对单个会话做判定。
pub fn evaluate(session: &SessionInfo, cfg: &RdpConfig, self_session_id: Option<u32>) -> RdpDecision {
    if !cfg.enabled {
        return RdpDecision::Allow("远程桌面保护未启用");
    }
    if Some(session.session_id) == self_session_id {
        return RdpDecision::Allow("本程序所在会话");
    }
    if !session.is_remote() {
        return RdpDecision::Allow("本地控制台会话，不属于远程接入");
    }
    if cfg.client_whitelist.is_empty() {
        return RdpDecision::Allow("客户端白名单为空，按配置不限制接入");
    }

    match session.client_name.as_deref() {
        Some(name) if matches_client(&cfg.client_whitelist, name) => {
            RdpDecision::Allow("客户端计算机名在白名单内")
        }
        Some(_) => RdpDecision::Block("客户端计算机名不在白名单内"),
        None => RdpDecision::Block("无法识别客户端计算机名"),
    }
}

/// 客户端名是否命中白名单。
///
/// 匹配规则（不区分大小写）：
/// - 完整名称相等；
/// - 以 `*` 结尾时按前缀匹配（例如 `SERVER-*` 覆盖 `SERVER-01`）。
pub fn matches_client(list: &[String], client: &str) -> bool {
    let client = client.trim();
    if client.is_empty() {
        return false;
    }
    let lower = client.to_lowercase();
    list.iter().any(|rule| {
        let rule = rule.trim().to_lowercase();
        if rule.is_empty() {
            return false;
        }
        match rule.strip_suffix('*') {
            Some(prefix) => lower.starts_with(prefix),
            None => lower == rule,
        }
    })
}

/// 一次巡查的结果。
#[derive(Clone, Debug, Default)]
pub struct SweepReport {
    /// 检查过的会话数。
    pub scanned: usize,
    /// 成功断开的会话。
    pub disconnected: Vec<u32>,
    /// 断开失败的会话及原因。
    pub failures: Vec<(u32, String)>,
}

impl SweepReport {
    pub fn has_action(&self) -> bool {
        !self.disconnected.is_empty() || !self.failures.is_empty()
    }
}

/// 巡查全部会话并按策略断开。
///
/// 断开动作**逐个上报结果**：失败必须记录并交给上层展示（规范 26.1），
/// 不允许静默跳过。
pub fn sweep(cfg: &RdpConfig) -> Result<SweepReport> {
    let mut report = SweepReport::default();
    if !cfg.enabled {
        return Ok(report);
    }

    let sessions = session::enumerate()?;
    let self_id = session::current_session_id();

    for s in &sessions {
        report.scanned += 1;
        if !evaluate(s, cfg, self_id).is_block() {
            continue;
        }
        match session::disconnect(s.session_id, false) {
            Ok(()) => report.disconnected.push(s.session_id),
            Err(e) => report.failures.push((s.session_id, e.to_string())),
        }
    }

    if !report.failures.is_empty() {
        // 有失败整体仍返回 Ok：报告里已经逐条记录了失败原因，
        // 调用方需要的是「部分成功」的完整视图，而不是被一个错误吞掉全部结果。
        return Ok(report);
    }
    Ok(report)
}

/// 校验配置中的客户端白名单写法是否合理。
pub fn validate(cfg: &RdpConfig) -> Vec<String> {
    let mut errs = Vec::new();
    if !cfg.enabled {
        return errs;
    }
    for rule in &cfg.client_whitelist {
        let r = rule.trim();
        if r.is_empty() {
            continue;
        }
        // 通配符只允许出现在末尾，中间的 * 会让匹配语义含糊。
        // 用 strip_suffix 而不是按下标切片，避免中文规则名触发非字符边界 panic。
        let without_trailing = r.strip_suffix('*').unwrap_or(r);
        if without_trailing.contains('*') {
            errs.push(format!(
                "RDP 客户端白名单「{}」：通配符 * 只能出现在末尾",
                rule
            ));
        }
    }
    if cfg.client_whitelist.iter().all(|r| r.trim().is_empty()) {
        errs.push("RDP 保护已启用，但客户端白名单为空，实际不会拦截任何连接".to_string());
    }
    errs
}

/// 便捷入口：启用状态下执行一次巡查；未启用时直接返回空报告。
pub fn run_once(cfg: &RdpConfig) -> Result<SweepReport> {
    if !cfg.enabled {
        return Ok(SweepReport::default());
    }
    if let Some(first) = validate(cfg).first() {
        return Err(AppError::Config(first.clone()));
    }
    sweep(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionState;

    fn remote(id: u32, client: &str) -> SessionInfo {
        SessionInfo {
            session_id: id,
            station: format!("RDP-Tcp#{}", id),
            state: SessionState::Active,
            client_name: Some(client.to_string()),
            user_name: Some("Administrator".to_string()),
        }
    }

    fn console(id: u32) -> SessionInfo {
        SessionInfo {
            session_id: id,
            station: "Console".to_string(),
            state: SessionState::Active,
            client_name: None,
            user_name: Some("Administrator".to_string()),
        }
    }

    fn cfg(enabled: bool, list: &[&str]) -> RdpConfig {
        RdpConfig {
            enabled,
            client_whitelist: list.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn 未启用时全部放行() {
        let d = evaluate(&remote(3, "EVIL-PC"), &cfg(false, &["DEV-PC"]), None);
        assert_eq!(d, RdpDecision::Allow("远程桌面保护未启用"));
    }

    #[test]
    fn 白名单命中的客户端放行() {
        let c = cfg(true, &["DEV-PC"]);
        assert!(!evaluate(&remote(3, "DEV-PC"), &c, None).is_block());
    }

    #[test]
    fn 匹配不区分大小写() {
        let c = cfg(true, &["dev-pc"]);
        assert!(!evaluate(&remote(3, "DEV-PC"), &c, None).is_block());
    }

    #[test]
    fn 未命中的客户端被断开() {
        let c = cfg(true, &["DEV-PC"]);
        let d = evaluate(&remote(3, "EVIL-PC"), &c, None);
        assert!(d.is_block());
        assert!(d.reason().contains("不在白名单"));
    }

    #[test]
    fn 本地控制台会话永不处理() {
        let c = cfg(true, &["DEV-PC"]);
        let d = evaluate(&console(0), &c, None);
        assert!(!d.is_block(), "控制台会话必须放行，否则管理员会被锁在门外");
        assert!(d.reason().contains("控制台"));
    }

    #[test]
    fn 本程序所在会话永不处理() {
        let c = cfg(true, &[]);
        let d = evaluate(&remote(7, "EVIL-PC"), &c, Some(7));
        assert!(!d.is_block());
        assert!(d.reason().contains("本程序"));
    }

    #[test]
    fn 白名单为空表示不限制() {
        let c = cfg(true, &[]);
        // 空名单不会拦截，避免一次误配置把服务器彻底锁死
        assert!(!evaluate(&remote(3, "ANY-PC"), &c, None).is_block());
    }

    #[test]
    fn 通配符前缀匹配() {
        let c = cfg(true, &["SERVER-*"]);
        assert!(!evaluate(&remote(3, "SERVER-01"), &c, None).is_block());
        assert!(evaluate(&remote(4, "SERVERX-01"), &c, None).is_block());
    }

    #[test]
    fn 客户端名匹配工具函数() {
        let list = vec!["dev-pc".to_string(), "SRV-*".to_string()];
        assert!(matches_client(&list, "DEV-PC"));
        assert!(matches_client(&list, "srv-09"));
        assert!(!matches_client(&list, "srv"));
        assert!(!matches_client(&list, ""));
        assert!(!matches_client(&[], "dev-pc"));
    }

    #[test]
    fn 校验能发现中间通配符() {
        let c = cfg(true, &["DEV-*-PC"]);
        let errs = validate(&c);
        assert!(!errs.is_empty());
        assert!(errs[0].contains("末尾"));
    }

    #[test]
    fn 校验提示空名单形同虚设() {
        let c = cfg(true, &[]);
        let errs = validate(&c);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("不会拦截"));
    }

    #[test]
    fn 未启用时校验通过() {
        assert!(validate(&cfg(false, &["DEV-*-PC"])).is_empty());
    }

    #[test]
    fn 未启用时巡查为空操作() {
        let r = run_once(&cfg(false, &[])).unwrap();
        assert_eq!(r.scanned, 0);
        assert!(!r.has_action());
    }
}
