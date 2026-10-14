//! 封停状态机。
//!
//! 规范 7：UI 与规则引擎都**不得**直接操作封停 Map，一切经过 `BanManager`。
//!
//! 规范 26.2：无论手动封停、黑名单、阈值触发还是恢复流程，
//! 最终都必须经过白名单硬校验，任何路径都不能封停白名单 IP。

use crate::config::Config;
use crate::error::{AppError, Result};
use crate::iprange::IpSet;
use crate::model::{BanReason, BanRecord, Ip};
use std::collections::HashMap;

/// 本程序创建的防火墙规则统一前缀。
///
/// 解封/清理时必须先校验该前缀，绝不按 IP 无条件删除系统或第三方规则（规范 8.4）。
pub const RULE_PREFIX: &str = "PortGuard-Ban-";

/// 为指定 IP 生成确定的规则名。
///
/// 采用明文 IP 而非哈希：长度可控（约 29 字符）、可读、便于运维在
/// `wf.msc` 中人工核对；同时 `RULE_PREFIX` 保证了清理时的精确筛选。
pub fn ban_rule_name(ip: Ip) -> String {
    format!("{}{}", RULE_PREFIX, ip)
}

/// 判断某个防火墙规则名是否由本程序创建。
pub fn is_own_rule(name: &str) -> bool {
    name.starts_with(RULE_PREFIX)
}

/// 封停管理器。
#[derive(Debug)]
pub struct BanManager {
    records: HashMap<u32, BanRecord>,
    /// 白名单快照，用于封停前硬校验。
    whitelist: IpSet,
}

impl Default for BanManager {
    fn default() -> Self {
        BanManager::new(IpSet::default())
    }
}

impl BanManager {
    pub fn new(whitelist: IpSet) -> Self {
        BanManager {
            records: HashMap::new(),
            whitelist,
        }
    }

    /// 更新白名单。更新后不在白名单内的既有封停记录保持不变——
    /// 是否解封由上层显式调用 `unban`，避免「改配置顺手放行攻击源」。
    pub fn set_whitelist(&mut self, whitelist: IpSet) {
        self.whitelist = whitelist;
    }

    /// 该 IP 是否命中白名单。
    #[inline]
    pub fn is_whitelisted(&self, ip: Ip) -> bool {
        self.whitelist.contains(ip)
    }

    /// 构造一条封停记录。
    pub fn make_record(
        &self,
        ip: Ip,
        reason: BanReason,
        cfg: &Config,
        now_ms: u64,
        protocol: Option<crate::model::Protocol>,
        service_port: Option<u16>,
        remote_port: Option<u16>,
        attempt_count: u32,
    ) -> BanRecord {
        let permanent = cfg.ban.permanent || reason == BanReason::Manual;
        let expires_at_ms = if permanent {
            None
        } else {
            Some(now_ms.saturating_add(cfg.ban.duration_seconds.saturating_mul(1000)))
        };
        BanRecord {
            ip,
            protocol,
            service_port,
            remote_port,
            attempt_count,
            created_at_ms: now_ms,
            expires_at_ms,
            permanent,
            reason,
            rule_name: ban_rule_name(ip),
        }
    }

    /// 写入/覆盖封停记录。
    ///
    /// 白名单命中时返回错误，调用方必须把错误暴露到 UI 与日志（规范 26.1 不假装成功）。
    pub fn ban(&mut self, record: BanRecord) -> Result<()> {
        if self.whitelist.contains(record.ip) {
            return Err(AppError::Other(format!(
                "{} 在白名单中，拒绝封停",
                record.ip
            )));
        }
        // 已存在时保留更严格的那条：永久封停不可被临时封停降级。
        if let Some(old) = self.records.get(&u32::from(record.ip)) {
            if old.permanent && !record.permanent {
                return Ok(());
            }
        }
        self.records.insert(u32::from(record.ip), record);
        Ok(())
    }

    /// 手动解封。返回是否真的移除了记录。
    pub fn unban(&mut self, ip: Ip) -> bool {
        self.records.remove(&u32::from(ip)).is_some()
    }

    /// 是否已封停。
    #[inline]
    pub fn is_banned(&self, ip: Ip) -> bool {
        self.records.contains_key(&u32::from(ip))
    }

    /// 查询封停记录。
    pub fn get(&self, ip: Ip) -> Option<&BanRecord> {
        self.records.get(&u32::from(ip))
    }

    /// 取出所有已到期记录并移除，返回需要执行解封的 IP 列表。
    pub fn take_expired(&mut self, now_ms: u64) -> Vec<Ip> {
        let expired: Vec<Ip> = self
            .records
            .values()
            .filter(|r| r.is_expired_at(now_ms))
            .map(|r| r.ip)
            .collect();
        for ip in &expired {
            self.records.remove(&u32::from(*ip));
        }
        expired
    }

    /// 重启恢复：加载持久化记录。
    ///
    /// 白名单命中的记录直接丢弃，保证「白名单永远优先」在重启后依然成立。
    ///
    /// 注意：**已到期的记录不在这里丢弃**。因为进程崩溃时对应的防火墙规则
    /// 可能仍然残留，必须走 `take_expired` 拿到 IP 列表后显式解封，
    /// 否则会泄漏防火墙规则（规范 26.3）。
    pub fn restore(&mut self, records: Vec<BanRecord>) {
        for r in records {
            if self.whitelist.contains(r.ip) {
                continue;
            }
            self.records.insert(u32::from(r.ip), r);
        }
    }

    /// 导出为持久化列表（按封停时间升序，输出稳定便于 diff）。
    pub fn snapshot(&self) -> Vec<BanRecord> {
        let mut v: Vec<BanRecord> = self.records.values().cloned().collect();
        v.sort_by(|a, b| {
            a.created_at_ms
                .cmp(&b.created_at_ms)
                .then_with(|| a.ip.cmp(&b.ip))
        });
        v
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// 永久封停数量。
    pub fn permanent_count(&self) -> usize {
        self.records.values().filter(|r| r.permanent).count()
    }

    /// 清空全部记录（仅用于测试与彻底重置）。
    pub fn clear(&mut self) {
        self.records.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn ip(s: &str) -> Ip {
        s.parse().unwrap()
    }

    fn mgr(whitelist: &[&str]) -> BanManager {
        let wl: Vec<String> = whitelist.iter().map(|s| s.to_string()).collect();
        BanManager::new(IpSet::from_rules(&wl).unwrap())
    }

    fn rec(m: &BanManager, addr: &str, reason: BanReason, now: u64) -> BanRecord {
        m.make_record(ip(addr), reason, &Config::with_defaults(), now, None, None, None, 1)
    }

    #[test]
    fn 封停与解封基本流程() {
        let mut m = mgr(&[]);
        let r = rec(&m, "1.2.3.4", BanReason::TcpThreshold, 1_000);
        assert!(m.ban(r).is_ok());
        assert!(m.is_banned(ip("1.2.3.4")));
        assert_eq!(m.len(), 1);
        assert!(m.unban(ip("1.2.3.4")));
        assert!(!m.is_banned(ip("1.2.3.4")));
        assert!(!m.unban(ip("1.2.3.4")));
    }

    #[test]
    fn 白名单地址拒绝封停() {
        let mut m = mgr(&["192.168.1.*"]);
        let r = rec(&m, "192.168.1.55", BanReason::TcpThreshold, 1_000);
        let err = m.ban(r);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("白名单"));
        assert!(!m.is_banned(ip("192.168.1.55")));
    }

    #[test]
    fn 白名单地址手动封停同样被拒绝() {
        // 规范 26.2 明确要求覆盖手动封停路径。
        let mut m = mgr(&["10.0.0.1"]);
        let r = rec(&m, "10.0.0.1", BanReason::Manual, 1_000);
        assert!(m.ban(r).is_err());
    }

    #[test]
    fn 临时封停到期被回收() {
        let mut m = mgr(&[]);
        let r = rec(&m, "1.2.3.4", BanReason::TcpThreshold, 1_000);
        m.ban(r).unwrap();
        // 默认封停 3600 秒
        assert!(m.take_expired(1_000 + 3_599_000).is_empty());
        let expired = m.take_expired(1_000 + 3_600_000);
        assert_eq!(expired, vec![ip("1.2.3.4")]);
        assert!(m.is_empty());
    }

    #[test]
    fn 永久封停不会到期() {
        let mut m = mgr(&[]);
        let cfg = Config {
            ban: crate::config::BanConfig {
                duration_seconds: 60,
                permanent: true,
            },
            ..Config::with_defaults()
        };
        let r = m.make_record(
            ip("1.2.3.4"),
            BanReason::Blacklist,
            &cfg,
            1_000,
            None,
            None,
            None,
            1,
        );
        assert!(r.permanent);
        assert_eq!(r.expires_at_ms, None);
        m.ban(r).unwrap();
        assert!(m.take_expired(u64::MAX / 2).is_empty());
        assert_eq!(m.permanent_count(), 1);
    }

    #[test]
    fn 手动封停默认永久() {
        let m = mgr(&[]);
        let r = rec(&m, "1.2.3.4", BanReason::Manual, 1_000);
        assert!(r.permanent);
    }

    #[test]
    fn 永久封停不会被临时封停降级() {
        let mut m = mgr(&[]);
        m.ban(rec(&m, "1.2.3.4", BanReason::Manual, 1_000)).unwrap();
        let mut tmp = rec(&m, "1.2.3.4", BanReason::TcpThreshold, 5_000);
        tmp.permanent = false;
        tmp.expires_at_ms = Some(9_000);
        m.ban(tmp).unwrap();
        let got = m.get(ip("1.2.3.4")).unwrap();
        assert!(got.permanent, "永久封停不应被临时封停覆盖");
        assert_eq!(got.created_at_ms, 1_000);
    }

    #[test]
    fn 临时封停可升级为永久() {
        let mut m = mgr(&[]);
        m.ban(rec(&m, "1.2.3.4", BanReason::TcpThreshold, 1_000))
            .unwrap();
        assert!(!m.get(ip("1.2.3.4")).unwrap().permanent);
        m.ban(rec(&m, "1.2.3.4", BanReason::Manual, 2_000)).unwrap();
        assert!(m.get(ip("1.2.3.4")).unwrap().permanent);
    }

    #[test]
    fn 恢复时丢弃白名单记录并可用到期回收清理防火墙() {
        let mut m = mgr(&["192.168.1.10"]);
        let cfg = Config::with_defaults();
        let mut a = m.make_record(ip("1.2.3.4"), BanReason::Manual, &cfg, 1_000, None, None, None, 1);
        let mut b = m.make_record(ip("5.6.7.8"), BanReason::Manual, &cfg, 1_000, None, None, None, 1);
        let mut c = m.make_record(ip("192.168.1.10"), BanReason::Manual, &cfg, 1_000, None, None, None, 1);
        a.permanent = true;
        b.permanent = false;
        b.expires_at_ms = Some(2_000);
        c.permanent = true;

        m.restore(vec![a, b, c]);
        // 白名单记录被丢弃；已到期的 5.6.7.8 保留，等待显式回收以清理防火墙规则
        assert_eq!(m.len(), 2);
        assert!(m.is_banned(ip("1.2.3.4")));
        assert!(m.is_banned(ip("5.6.7.8")));

        let expired = m.take_expired(51_000);
        assert_eq!(expired, vec![ip("5.6.7.8")]);
        assert_eq!(m.len(), 1);
        assert!(m.is_banned(ip("1.2.3.4")));
    }

    #[test]
    fn 快照按封停时间稳定排序() {
        let mut m = mgr(&[]);
        m.ban(rec(&m, "9.9.9.9", BanReason::Manual, 3_000)).unwrap();
        m.ban(rec(&m, "1.1.1.1", BanReason::Manual, 1_000)).unwrap();
        m.ban(rec(&m, "5.5.5.5", BanReason::Manual, 2_000)).unwrap();
        let snap = m.snapshot();
        assert_eq!(snap[0].ip, ip("1.1.1.1"));
        assert_eq!(snap[2].ip, ip("9.9.9.9"));
    }

    #[test]
    fn 规则名前缀可识别归属() {
        let n = ban_rule_name(ip("1.2.3.4"));
        assert_eq!(n, "PortGuard-Ban-1.2.3.4");
        assert!(is_own_rule(&n));
        assert!(!is_own_rule("远程桌面 (TCP-In)"));
        assert!(!is_own_rule("PortGuard-Protect-RiskyPorts-TCP"));
    }
}
