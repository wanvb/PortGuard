//! `PortGuardApi` 的实现。
//!
//! 本层只做三件事：把运行状态翻译成面板视图、把用户操作翻译成后台动作、
//! 把配置变更落到磁盘。所有方法都保证快速返回（规范 44）：
//! 慢操作一律交给 `runtime` 的执行线程。

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use portguard_core::api::{
    protocol_label, AdapterView, BanView, ConnectionView, EventView, PortGuardApi,
    ProtectionSwitch, StatusView,
};
use portguard_core::config::Config;
use portguard_core::error::{AppError, Result};
use portguard_core::iprange::{parse_ipv4, IpSet};
use portguard_core::logging::LogLine;
use portguard_core::model::{BanReason, Ip, Statistics};
use portguard_core::time::now_ms;
use portguard_geo::GeoLookup;
use portguard_storage::{AppPaths, ConfigStore, Logger};

use crate::runtime::{Action, BanRequest, RuntimeHandle};

/// 面板与托盘共用的控制器。
pub struct Controller {
    rt: Arc<RuntimeHandle>,
    store: ConfigStore,
    logger: Arc<Logger>,
    /// 数据目录与程序目录，用于定位地理位置库。
    paths: AppPaths,
    /// 地理位置库。只服务于展示，**绝不参与封停判定**（规范 22），
    /// 因此加锁访问也不与判定路径产生任何耦合。
    geo: RwLock<GeoLookup>,
}

/// 地理位置库的候选路径。
///
/// 顺序：绝对路径（用户显式指定）→ 数据目录 `data/` → 程序目录 → 当前工作目录。
/// 前三者是部署形态；工作目录只作末位兜底，让「在资料目录里直接运行
/// `target/release/PortGuard.exe`」也能找到库文件，且因排在最后，
/// 永远不会覆盖前面几处的同名文件。
fn geo_candidates(paths: &AppPaths, db: &str) -> Vec<PathBuf> {
    let name = Path::new(db);
    if name.is_absolute() {
        return vec![name.to_path_buf()];
    }
    let mut candidates = vec![paths.data_dir().join(name), paths.root().join(name)];
    if let Ok(cwd) = std::env::current_dir() {
        let path = cwd.join(name);
        if !candidates.contains(&path) {
            candidates.push(path);
        }
    }
    candidates
}

/// 把地理位置库状态写进日志。
///
/// 库缺失不算错误（规范 22：只影响展示），但必须让用户知道文件该放哪，
/// 否则面板上的一片「未知」会被当成程序故障。
fn report_geo(logger: &Logger, lookup: &GeoLookup) {
    if lookup.ready() {
        logger.info(format!("地理位置库已加载：{}", lookup.status()));
    } else {
        logger.warn(format!("地理位置不可用：{}", lookup.status()));
    }
}

impl Controller {
    pub fn new(rt: Arc<RuntimeHandle>, paths: AppPaths, logger: Arc<Logger>) -> Controller {
        let cfg = rt.config();
        let geo = GeoLookup::load(cfg.geo.enabled, &geo_candidates(&paths, &cfg.geo.db));
        report_geo(&logger, &geo);
        Controller {
            rt,
            store: ConfigStore::new(paths.config_file()),
            logger,
            paths,
            geo: RwLock::new(geo),
        }
    }

    /// 以读锁访问地理位置库；锁中毒时沿用内部数据，不阻断面板。
    fn with_geo<T>(&self, f: impl FnOnce(&GeoLookup) -> T) -> T {
        match self.geo.read() {
            Ok(guard) => f(&guard),
            Err(poisoned) => f(&poisoned.into_inner()),
        }
    }

    /// 按新配置重新加载地理位置库（开启/关闭、换库路径都要真的生效）。
    fn reload_geo(&self, cfg: &Config) {
        let lookup = GeoLookup::load(cfg.geo.enabled, &geo_candidates(&self.paths, &cfg.geo.db));
        report_geo(&self.logger, &lookup);
        let mut guard = match self.geo.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = lookup;
    }

    /// 取一个 IP 的展示用地理位置。
    ///
    /// 在运行期锁之外调用：地理位置查询与判定无关，不该占用抓包与执行线程的锁。
    fn location_of(&self, ip: &str) -> String {
        self.with_geo(|geo| geo.describe(ip))
    }

    /// 校验、落盘并应用配置。落盘失败则内存状态保持不变。
    fn commit(&self, cfg: Config) -> Result<Config> {
        let mut cfg = cfg;
        cfg.normalize();
        let errs = cfg.validate();
        if !errs.is_empty() {
            return Err(AppError::Config(errs.join("；")));
        }
        self.store.save(&cfg)?;
        self.rt.apply_config(cfg.clone())?;
        Ok(cfg)
    }

    /// 读取白名单集合（用于封停前的硬校验，避免把禁用地址拦在外面）。
    fn whitelist(&self) -> Result<IpSet> {
        IpSet::from_rules(&self.rt.config().lists.whitelist)
    }
}

impl PortGuardApi for Controller {
    fn status(&self) -> StatusView {
        let cfg = self.rt.config();
        let now = now_ms();
        let uptime = now.saturating_sub(self.rt.started_at_ms()) / 1000;
        self.rt.read(|inner| {
            let adapter = match inner.local_ip {
                Some(ip) => ip.to_string(),
                None => String::new(),
            };
            StatusView {
                running: inner.running(),
                adapter: adapter.clone(),
                local_ip: adapter,
                panel_bind: cfg.panel.bind.clone(),
                admin: portguard_win::is_elevated(),
                capture_ready: inner.running(),
                stats: Statistics {
                    tracking: inner.engine.tracker.len() as u64,
                    banned: inner.bans.len() as u64,
                    permanent: inner.bans.permanent_count() as u64,
                    captured_packets: inner.captured_packets,
                    total_bans: inner.total_bans,
                    uptime_seconds: uptime,
                },
                started_at_ms: self.rt.started_at_ms(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                protected_ports: inner.engine.protected_port_count(),
                risky_ports: cfg.system.risky_ports,
                block_icmp: cfg.system.block_icmp,
                autostart: cfg.system.autostart,
                rdp_enabled: cfg.rdp.enabled,
                geo_ready: self.with_geo(|geo| geo.ready()),
                geo_status: self.with_geo(|geo| geo.status().to_string()),
            }
        })
    }

    fn connections(&self) -> Vec<ConnectionView> {
        let mut rows = self.rt.read(|inner| inner.connection_rows());
        for row in rows.iter_mut() {
            let location = self.location_of(&row.ip);
            row.location = location;
        }
        rows
    }

    fn bans(&self) -> Vec<BanView> {
        let now = now_ms();
        let mut rows: Vec<BanView> = self.rt.read(|inner| {
            let mut rows: Vec<BanView> = inner
                .bans
                .snapshot()
                .into_iter()
                .map(|r| BanView {
                    ip: r.ip.to_string(),
                    reason: r.reason.as_str().to_string(),
                    reason_label: r.reason.label().to_string(),
                    protocol: protocol_label(r.protocol),
                    service_port: r.service_port,
                    remote_port: r.remote_port,
                    attempt_count: r.attempt_count,
                    created_at_ms: r.created_at_ms,
                    expires_at_ms: r.expires_at_ms,
                    permanent: r.permanent,
                    remaining_seconds: r.remaining_seconds(now),
                    rule_name: r.rule_name.clone(),
                    location: String::new(),
                })
                .collect();
            // 最新的排在最前
            rows.sort_by(|a, b| b.created_at_ms.cmp(&a.created_at_ms));
            rows
        });

        for row in rows.iter_mut() {
            let location = self.location_of(&row.ip);
            row.location = location;
        }
        rows
    }

    fn config(&self) -> Config {
        self.rt.config()
    }

    fn save_config(&self, cfg: Config) -> Result<Config> {
        let before = self.rt.config();
        // 网卡变更要真正重启抓包，失败必须让用户看到
        if before.network.adapter != cfg.network.adapter && !cfg.network.adapter.trim().is_empty() {
            self.rt.select_adapter(cfg.network.adapter.trim())?;
        }
        let saved = self.commit(cfg)?;
        // 地理位置库的开关与路径改了要立即生效，否则用户会以为设置没保存成功
        if saved.geo != before.geo {
            self.reload_geo(&saved);
        }
        Ok(saved)
    }

    fn start(&self) -> Result<()> {
        let r = self.rt.start();
        if let Err(e) = &r {
            self.logger.error(format!("开始保护失败：{}", e));
        }
        r
    }

    fn stop(&self) -> Result<()> {
        self.rt.stop();
        Ok(())
    }

    fn ban_ip(&self, ip: Ip, permanent: bool) -> Result<()> {
        if self.whitelist()?.contains(ip) {
            return Err(AppError::Other(format!("{} 在白名单中，拒绝封停", ip)));
        }
        let ok = self.rt.enqueue(Action::Ban(BanRequest {
            ip,
            reason: BanReason::Manual,
            protocol: None,
            service_port: None,
            remote_port: None,
            attempt_count: 0,
            permanent_override: Some(permanent),
        }));
        if !ok {
            return Err(AppError::Other("后台执行线程已停止，封停未生效".to_string()));
        }
        self.logger.info(format!(
            "手动封停 {}（{}）",
            ip,
            if permanent { "永久" } else { "限时" }
        ));
        Ok(())
    }

    fn unban_ip(&self, ip: Ip) -> Result<()> {
        self.rt.enqueue(Action::Unban(ip));
        self.logger.info(format!("手动解封 {}", ip));
        Ok(())
    }

    fn whitelist_add(&self, rule: &str) -> Result<()> {
        let rule = rule.trim();
        if rule.is_empty() {
            return Err(AppError::InvalidIpRule("规则不能为空".to_string()));
        }
        let mut cfg = self.rt.config();
        if cfg.lists.whitelist.iter().any(|r| r == rule) {
            return Ok(());
        }
        cfg.lists.whitelist.push(rule.to_string());
        // 先校验整份名单，避免加入半条非法规则
        let set = IpSet::from_rules(&cfg.lists.whitelist)?;
        self.commit(cfg)?;

        // 白名单优先级最高：已封停的地址立即解封
        let to_free: Vec<Ip> = self.rt.read(|inner| {
            inner
                .bans
                .snapshot()
                .into_iter()
                .filter(|r| set.contains(r.ip))
                .map(|r| r.ip)
                .collect()
        });
        for ip in to_free {
            self.rt.enqueue(Action::Unban(ip));
        }
        Ok(())
    }

    fn blacklist_add(&self, rule: &str) -> Result<()> {
        let rule = rule.trim();
        if rule.is_empty() {
            return Err(AppError::InvalidIpRule("规则不能为空".to_string()));
        }
        let mut cfg = self.rt.config();
        if cfg.lists.blacklist.iter().any(|r| r == rule) {
            return Ok(());
        }
        cfg.lists.blacklist.push(rule.to_string());
        IpSet::from_rules(&cfg.lists.blacklist)?;
        self.commit(cfg)?;

        // 黑名单立即生效：单地址规则直接封停；
        // 网段 / 通配规则不展开（可能是数百万地址），交给抓包判定在首个包时封停。
        if let Ok(ip) = parse_ipv4(rule) {
            if !self.whitelist()?.contains(ip) {
                self.rt.enqueue(Action::Ban(BanRequest {
                    ip,
                    reason: BanReason::Blacklist,
                    protocol: None,
                    service_port: None,
                    remote_port: None,
                    attempt_count: 0,
                    permanent_override: None,
                }));
            }
        }
        Ok(())
    }

    fn whitelist_remove(&self, rule: &str) -> Result<()> {
        let mut cfg = self.rt.config();
        let before = cfg.lists.whitelist.len();
        cfg.lists.whitelist.retain(|r| r != rule);
        if cfg.lists.whitelist.len() == before {
            return Ok(());
        }
        self.commit(cfg)?;
        Ok(())
    }

    fn blacklist_remove(&self, rule: &str) -> Result<()> {
        let mut cfg = self.rt.config();
        let before = cfg.lists.blacklist.len();
        cfg.lists.blacklist.retain(|r| r != rule);
        if cfg.lists.blacklist.len() == before {
            return Ok(());
        }
        self.commit(cfg)?;
        Ok(())
    }

    fn logs(&self, limit: usize) -> Vec<LogLine> {
        self.rt.logs(limit)
    }

    fn events(&self, limit: usize) -> Vec<EventView> {
        self.rt.read(|inner| inner.events.iter().take(limit).cloned().collect())
    }

    fn adapters(&self) -> Vec<AdapterView> {
        let cfg = self.rt.config();
        let selected = self.rt.read(|inner| inner.local_ip);
        match portguard_packet::enumerate(cfg.network.include_virtual) {
            Ok(list) => list
                .into_iter()
                .map(|a| AdapterView {
                    ip: a.ip.to_string(),
                    mask: a.mask.clone(),
                    description: a.description.clone(),
                    is_virtual: a.is_virtual,
                    selected: Some(a.ip) == selected,
                    usable: a.is_usable(),
                })
                .collect(),
            Err(e) => {
                self.logger.warn(format!("网卡枚举失败：{}", e));
                Vec::new()
            }
        }
    }

    fn select_adapter(&self, ip: &str) -> Result<()> {
        let ip = ip.trim();
        self.rt.select_adapter(ip)?;
        // 抓包已经切到新网卡，配置必须跟上，否则下次启动会退回旧网卡
        let cfg = self.rt.config();
        if let Err(e) = self.store.save(&cfg) {
            self.logger.warn(format!(
                "网卡已切换为 {}，但配置写入失败：{}",
                ip, e
            ));
            return Err(e);
        }
        Ok(())
    }

    fn set_protection(&self, key: ProtectionSwitch, enabled: bool) -> Result<()> {
        match key {
            ProtectionSwitch::Autostart => {
                let exe = std::env::current_exe()
                    .map_err(|e| AppError::Other(format!("无法确定程序路径：{}", e)))?;
                if enabled {
                    portguard_win::Autostart::enable(&exe)?;
                } else {
                    portguard_win::Autostart::disable()?;
                }
                let mut cfg = self.rt.config();
                cfg.system.autostart = enabled;
                self.commit(cfg)?;
                Ok(())
            }
            ProtectionSwitch::RdpGuard => {
                let mut cfg = self.rt.config();
                cfg.rdp.enabled = enabled;
                self.commit(cfg)?;
                Ok(())
            }
            ProtectionSwitch::RiskyPorts => {
                let mut cfg = self.rt.config();
                cfg.system.risky_ports = enabled;
                self.commit(cfg)?;
                Ok(())
            }
            ProtectionSwitch::BlockIcmp => {
                let mut cfg = self.rt.config();
                cfg.system.block_icmp = enabled;
                self.commit(cfg)?;
                Ok(())
            }
        }
    }

    fn data_dir(&self) -> String {
        self.rt.data_dir()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portguard_core::logging::Level;
    use portguard_firewall::MockFirewall;

    fn temp_paths() -> AppPaths {
        let dir = std::env::temp_dir().join(format!(
            "pg_ctrl_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        AppPaths::with_root(dir)
    }

    fn controller() -> (Controller, AppPaths) {
        let paths = temp_paths();
        let logger = Arc::new(
            Logger::start(&paths.log_file(), Level::Error, 64).expect("创建测试日志器失败"),
        );
        let fw = Arc::new(MockFirewall::new());
        let rt = Arc::new(RuntimeHandle::new(
            Config::with_defaults(),
            Arc::clone(&logger),
            fw,
            paths.clone(),
        ));
        (
            Controller::new(rt, paths.clone(), logger),
            paths,
        )
    }

    #[test]
    fn 白名单地址拒绝手动封停() {
        let (c, _) = controller();
        let mut cfg = c.config();
        cfg.lists.whitelist = vec!["203.0.113.5".to_string()];
        c.save_config(cfg).unwrap();

        let err = c.ban_ip("203.0.113.5".parse().unwrap(), true).unwrap_err();
        assert!(err.to_string().contains("白名单"));
    }

    #[test]
    fn 加入白名单会写入配置文件() {
        let (c, paths) = controller();
        c.whitelist_add("198.51.100.9").unwrap();
        assert!(c.config().lists.whitelist.contains(&"198.51.100.9".to_string()));

        let text = std::fs::read_to_string(paths.config_file()).unwrap();
        assert!(text.contains("198.51.100.9"), "配置必须落盘：{}", text);
    }

    #[test]
    fn 非法名单规则被拒绝且不改配置() {
        let (c, _) = controller();
        assert!(c.whitelist_add("这不是IP").is_err());
        assert!(c.config().lists.whitelist.is_empty());
        assert!(c.blacklist_add("1.2.3.4.5").is_err());
        assert!(c.config().lists.blacklist.is_empty());
    }

    #[test]
    fn 重复加入名单不会产生重复项() {
        let (c, _) = controller();
        c.blacklist_add("10.1.1.1").unwrap();
        c.blacklist_add("10.1.1.1").unwrap();
        assert_eq!(c.config().lists.blacklist.len(), 1);
    }

    #[test]
    fn 删除不存在的规则是幂等的() {
        let (c, _) = controller();
        assert!(c.whitelist_remove("1.1.1.1").is_ok());
        assert!(c.blacklist_remove("1.1.1.1").is_ok());
    }

    #[test]
    fn 状态统计与列表长度一致() {
        let (c, _) = controller();
        let st = c.status();
        assert_eq!(st.stats.tracking, c.connections().len() as u64);
        assert_eq!(st.stats.banned, c.bans().len() as u64);
        assert!(!st.version.is_empty());
        assert_eq!(st.protected_ports, 4, "默认 3389 + 3389 + 80 + 443");
    }

    #[test]
    fn 非法配置被拒绝且不覆盖已保存的文件() {
        let (c, paths) = controller();
        c.save_config(Config::with_defaults()).unwrap();
        let before = std::fs::read_to_string(paths.config_file()).unwrap();

        let mut bad = c.config();
        bad.lists.whitelist = vec!["坏规则".to_string()];
        assert!(c.save_config(bad).is_err());

        let after = std::fs::read_to_string(paths.config_file()).unwrap();
        assert_eq!(before, after, "非法配置不得落盘");
    }

    #[test]
    fn 切换非法网卡地址被拒绝() {
        let (c, _) = controller();
        assert!(c.select_adapter("999.1.1.1").is_err());
        assert!(c.config().network.adapter.is_empty());
    }

    #[test]
    fn 地理位置库候选路径优先数据目录() {
        let paths = AppPaths::with_root("D:/PortGuard");
        let list = geo_candidates(&paths, "ip2region_v4.xdb");
        assert!(list.len() >= 2, "至少要有数据目录与程序目录两个候选");
        assert!(list[0].ends_with(Path::new("data").join("ip2region_v4.xdb")));
        assert!(list[1].ends_with("ip2region_v4.xdb"));
        assert!(
            list[2..].iter().all(|p| p.ends_with("ip2region_v4.xdb")),
            "兜底候选同样指向同名文件：{:?}",
            list
        );

        // 用户写绝对路径时不再拼接，避免出现 data/D:/xxx 这种荒唐结果
        let abs = geo_candidates(&paths, "D:/elsewhere/ip.db");
        assert_eq!(abs.len(), 1);
    }

    #[test]
    fn 数据库缺失时地理位置恒为未知() {
        let (c, _) = controller();
        assert!(!c.status().geo_ready);
        assert_eq!(c.location_of("8.8.8.8"), "未知");
        assert_eq!(c.location_of("不是IP"), "未知");
    }

    #[test]
    fn 保存配置后地理位置库立即重载() {
        // 数据库不随源码分发，缺失时跳过（不影响 CI）
        let real = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ip2region_v4.xdb");
        if !real.is_file() {
            return;
        }
        let (c, paths) = controller();
        assert!(!c.status().geo_ready, "临时目录里还没有库");

        std::fs::create_dir_all(paths.data_dir()).unwrap();
        std::fs::copy(&real, paths.data_dir().join("ip2region_v4.xdb")).unwrap();

        // 关闭后不得再显示地理位置
        let mut cfg = c.config();
        cfg.geo.enabled = false;
        c.save_config(cfg).unwrap();
        assert!(!c.status().geo_ready);
        assert_eq!(c.location_of("8.8.8.8"), "未知");

        // 重新开启必须立刻加载成功，而不是等下次启动
        let mut cfg = c.config();
        cfg.geo.enabled = true;
        c.save_config(cfg).unwrap();
        assert!(c.status().geo_ready, "库已就位却未加载");
        assert!(c.location_of("8.8.8.8").contains("United States"));
    }
}
