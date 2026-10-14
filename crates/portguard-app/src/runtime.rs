//! 运行期业务回路。
//!
//! 线程模型（规范 42：抓包线程绝不做阻塞 I/O）：
//!
//! ```text
//! 抓包线程 ──► 锁内判定（纯内存）──► 动作队列 ──► 执行线程（netsh / 落盘）
//! Web 线程 ──► 锁内读快照 / 入队 ─────────────► 执行线程
//! ```
//!
//! 抓包线程只做「判定 + 入队」，防火墙调用与文件写入全部落在执行线程，
//! 因此高流量下也不会因为一次 netsh 调用而丢包。

use std::collections::{HashSet, VecDeque};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use portguard_core::ban::{ban_rule_name, BanManager};
use portguard_core::api::{ConnectionView, EventView};
use portguard_core::config::Config;
use portguard_core::engine::RuleEngine;
use portguard_core::error::{AppError, Result};
use portguard_core::iprange::{parse_ipv4, IpSet};
use portguard_core::logging::{Level, LogLine};
use portguard_core::model::{BanReason, Ip, PacketInfo, PortGroup, Protocol};
use portguard_core::time::now_ms;
use portguard_firewall::{cleanup_orphans, FirewallBackend, RuleDirection};
use portguard_packet::{capture, CaptureHandle};
use portguard_rdp::policy as rdp_policy;
use portguard_storage::{AppPaths, BanStore, Logger};

/// 面板连接列表的回看窗口：超过该时长未再出现的条目不再展示。
const CONNECTION_TTL_MS: u64 = 5 * 60 * 1000;

/// 事件流保留条数。
const MAX_EVENTS: usize = 200;

/// 跟踪表清理周期与保留时长。
const PRUNE_PASS: Duration = Duration::from_secs(5);
const TRACK_RETENTION_MS: u64 = 10 * 60 * 1000;

/// RDP 巡检的最小间隔（避免高频枚举会话）。
const RDP_PASS: Duration = Duration::from_secs(15);

/// 一次封停请求。
#[derive(Clone, Debug)]
pub struct BanRequest {
    pub ip: Ip,
    pub reason: BanReason,
    pub protocol: Option<Protocol>,
    pub service_port: Option<u16>,
    pub remote_port: Option<u16>,
    pub attempt_count: u32,
    /// 界面手动封停时由用户指定；自动封停为 `None`，跟随配置。
    pub permanent_override: Option<bool>,
}

/// 后台动作：所有慢操作都经由执行线程串行完成。
#[derive(Clone, Debug)]
pub enum Action {
    /// 封停（阈值 / 黑名单 / 手动）。
    Ban(BanRequest),
    /// 解封（到期 / 手动）。
    Unban(Ip),
    /// 重新应用系统级保护规则（危险端口、禁 Ping）。
    SyncSystemRules,
}

/// 共享运行状态。所有字段都在同一把锁下，保证快照一致。
pub struct Inner {
    pub config: Config,
    pub engine: RuleEngine,
    pub bans: BanManager,
    pub events: VecDeque<EventView>,
    pub capture: Option<CaptureHandle>,
    /// 当前抓包网卡地址；`None` 表示尚未选择。
    pub local_ip: Option<Ip>,
    /// 选定网卡的描述，用于面板展示。
    pub adapter_desc: String,
    pub captured_packets: u64,
    pub total_bans: u64,
    /// 已入队但尚未落到防火墙的 IP，避免同一攻击源重复排队。
    pending: HashSet<u32>,
}

/// 抓包回调侧的最小上下文，避免把整个句柄塞进闭包。
struct PacketSink {
    inner: Arc<Mutex<Inner>>,
    tx: Sender<Action>,
    logger: Arc<Logger>,
}

impl PacketSink {
    /// 处理一个包：判定 + 必要时入队。
    fn consume(&self, mut pkt: PacketInfo) {
        // 解析层不填时间戳，由采集侧回填（规范 3.2 的职责划分）。
        pkt.timestamp_ms = now_ms();

        let mut g = lock_inner(&self.inner);
        g.captured_packets = g.captured_packets.saturating_add(1);

        let local_ip = match g.local_ip {
            Some(ip) => ip,
            None => return,
        };
        let peer = pkt.peer_ip(local_ip);
        let outcome = g.engine.evaluate(&pkt);

        if !outcome.should_ban() {
            return;
        }
        // 已封停或在途的来源不再重复排队，否则一次扫描会灌满队列。
        if g.bans.is_banned(peer) || g.pending.contains(&u32::from(peer)) {
            return;
        }

        let request = BanRequest {
            ip: peer,
            reason: reason_of(&outcome),
            protocol: Some(pkt.protocol),
            service_port: Some(pkt.service_port(local_ip)),
            remote_port: Some(pkt.remote_port(local_ip)),
            attempt_count: attempt_count_of(&outcome),
            permanent_override: None,
        };
        g.pending.insert(u32::from(peer));
        drop(g);

        if self.tx.send(Action::Ban(request)).is_err() {
            // 执行线程已退出（程序正在收尾），此时无需再纠正状态。
            self.logger
                .debug("封停动作未送达执行线程：执行线程已停止".to_string());
        }
    }

    fn on_capture_error(&self, message: String) {
        self.logger.error(format!("抓包出错：{}", message));
        let mut g = lock_inner(&self.inner);
        g.push_event("error", format!("抓包出错：{}", message), None);
    }
}

/// 判定结果 → 封停原因。
fn reason_of(outcome: &portguard_core::engine::Outcome) -> BanReason {
    use portguard_core::engine::Outcome;
    match outcome {
        Outcome::BlacklistBan => BanReason::Blacklist,
        Outcome::ThresholdBan { group, .. } => match group {
            PortGroup::Tcp => BanReason::TcpThreshold,
            PortGroup::Web => BanReason::WebThreshold,
            PortGroup::Udp => BanReason::UdpThreshold,
        },
        _ => BanReason::Manual,
    }
}

/// 判定结果 → 触发次数。
fn attempt_count_of(outcome: &portguard_core::engine::Outcome) -> u32 {
    match outcome {
        portguard_core::engine::Outcome::ThresholdBan { count, .. } => *count,
        _ => 0,
    }
}

impl Inner {
    /// 追加一条事件（最新的在最前），超出上限丢弃最旧。
    pub fn push_event(&mut self, kind: &str, message: String, ip: Option<String>) {
        self.events.push_front(EventView {
            ts_ms: now_ms(),
            kind: kind.to_string(),
            message,
            ip,
        });
        while self.events.len() > MAX_EVENTS {
            self.events.pop_back();
        }
    }

    /// 是否正在抓包（句柄存在且线程仍活着）。
    pub fn running(&self) -> bool {
        self.capture
            .as_ref()
            .map(|c| c.is_running())
            .unwrap_or(false)
    }

    /// 生成面板用的连接行。
    pub fn connection_rows(&self) -> Vec<ConnectionView> {
        let now = now_ms();
        let cfg = &self.config;
        self.engine
            .connection_rows(now, CONNECTION_TTL_MS)
            .into_iter()
            .map(|row| {
                let rule = match row.group {
                    PortGroup::Tcp => &cfg.protect.tcp,
                    PortGroup::Web => &cfg.protect.http,
                    PortGroup::Udp => &cfg.protect.udp,
                };
                let whitelisted = self.engine.is_whitelisted(row.ip);
                let state = if whitelisted {
                    "WHITELIST"
                } else if self.bans.is_banned(row.ip) {
                    match self.bans.get(row.ip) {
                        Some(r) if r.permanent => "PERMANENT",
                        _ => "BANNED",
                    }
                } else {
                    "TRACKING"
                };
                ConnectionView {
                    ip: row.ip.to_string(),
                    group: row.group.as_str().to_string(),
                    service_port: row.port,
                    count: row.window_count,
                    total_count: row.total_count,
                    first_seen_ms: row.first_seen_ms,
                    last_seen_ms: row.last_seen_ms,
                    threshold: rule.max_attempts,
                    state: state.to_string(),
                    whitelisted,
                }
            })
            .collect()
    }
}

/// 取锁；锁中毒时继续使用内部数据（本模块不会在持锁期间 panic，
/// 真中毒了也不该让整个程序停摆）。
fn lock_inner(inner: &Arc<Mutex<Inner>>) -> MutexGuard<'_, Inner> {
    inner.lock().unwrap_or_else(|e| e.into_inner())
}

/// 运行期句柄：对外暴露的全部操作入口。
pub struct RuntimeHandle {
    inner: Arc<Mutex<Inner>>,
    tx: Sender<Action>,
    logger: Arc<Logger>,
    paths: AppPaths,
    started_at_ms: u64,
}

impl RuntimeHandle {
    /// 建立运行时，并启动后台执行线程。
    ///
    /// 启动时会把上次遗留的孤儿防火墙规则清理掉（规范 8.4：只删本程序前缀的规则）。
    pub fn new(
        config: Config,
        logger: Arc<Logger>,
        firewall: Arc<dyn FirewallBackend>,
        paths: AppPaths,
    ) -> RuntimeHandle {
        let local_ip = parse_ipv4(&config.network.adapter).ok();
        let whitelist = IpSet::from_rules(&config.lists.whitelist).unwrap_or_default();
        let bans = match BanStore::load(&paths.bans_file()) {
            Ok(store) => {
                let n = store.bans.len();
                if n > 0 {
                    logger.info(format!("已恢复 {} 条封停记录", n));
                }
                let mut mgr = BanManager::new(whitelist);
                mgr.restore(store.bans);
                mgr
            }
            Err(e) => {
                logger.warn(format!("封停记录读取失败，本次以空列表启动：{}", e));
                BanManager::new(whitelist)
            }
        };

        let inner = Arc::new(Mutex::new(Inner {
            engine: RuleEngine::new(&config, local_ip.unwrap_or(Ip::UNSPECIFIED)),
            config,
            bans,
            events: VecDeque::new(),
            capture: None,
            local_ip,
            adapter_desc: String::new(),
            captured_packets: 0,
            total_bans: 0,
            pending: HashSet::new(),
        }));

        let (tx, rx) = mpsc::channel::<Action>();
        let handle = RuntimeHandle {
            inner: Arc::clone(&inner),
            tx,
            logger: Arc::clone(&logger),
            paths: paths.clone(),
            started_at_ms: now_ms(),
        };

        spawn_worker(inner, rx, firewall, logger, paths);
        handle
    }

    /// 只读访问共享状态。
    pub fn read<R>(&self, f: impl FnOnce(&Inner) -> R) -> R {
        let g = lock_inner(&self.inner);
        f(&g)
    }

    /// 可变访问共享状态（仅供测试构造边界场景）。
    #[cfg(test)]
    pub fn write<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        let mut g = lock_inner(&self.inner);
        f(&mut g)
    }

    /// 取配置快照。
    pub fn config(&self) -> Config {
        self.read(|inner| inner.config.clone())
    }

    /// 进程启动时间（Unix 纪元毫秒）。
    pub fn started_at_ms(&self) -> u64 {
        self.started_at_ms
    }

    /// 数据目录。
    pub fn data_dir(&self) -> String {
        self.paths.data_dir().display().to_string()
    }

    /// 把动作交给执行线程。
    pub fn enqueue(&self, action: Action) -> bool {
        self.tx.send(action).is_ok()
    }

    /// 立即写入封停记录文件（在调用线程内完成，仅用于退出前收尾）。
    pub fn persist_bans(&self) {
        let records = self.read(|inner| inner.bans.snapshot());
        if let Err(e) = BanStore::new(records).save(&self.paths.bans_file()) {
            self.logger.error(format!("封停记录写入失败：{}", e));
        }
    }

    /// 开始保护。
    pub fn start(&self) -> Result<()> {
        let mut g = lock_inner(&self.inner);
        if g.running() {
            return Ok(());
        }
        let ip = match g.local_ip {
            Some(ip) => ip,
            None => {
                return Err(AppError::Other(
                    "尚未选择监听网卡，请先在设置页选择".to_string(),
                ))
            }
        };

        let handle = start_capture(&self.inner, &self.tx, &self.logger, ip)?;
        g.capture = Some(handle);
        g.engine.set_local_ip(ip);
        g.push_event("system", format!("已开始保护：{}", ip), Some(ip.to_string()));
        drop(g);

        self.logger.info(format!("抓包已启动，监听 {}", ip));
        // 系统级规则随保护启动一并应用
        self.enqueue(Action::SyncSystemRules);
        Ok(())
    }

    /// 停止保护（保留封停记录）。
    pub fn stop(&self) {
        let mut g = lock_inner(&self.inner);
        if let Some(mut h) = g.capture.take() {
            drop(g);
            h.stop();
            self.logger.info("抓包已停止".to_string());
            let mut g = lock_inner(&self.inner);
            g.push_event("system", "保护已停止".to_string(), None);
            drop(g);
        }
    }

    /// 切换监听网卡：先停旧网卡，再按新地址重启。
    pub fn select_adapter(&self, ip_text: &str) -> Result<()> {
        let ip = parse_ipv4(ip_text)
            .map_err(|_| AppError::InvalidIpRule(format!("网卡地址非法：{}", ip_text)))?;

        let was_running = self.read(|inner| inner.running());
        if was_running {
            self.stop();
        }

        // 记录网卡描述供面板展示；枚举失败不影响使用。
        let desc = portguard_packet::enumerate(false)
            .ok()
            .and_then(|list| list.into_iter().find(|a| a.ip == ip))
            .map(|a| a.description)
            .unwrap_or_default();

        {
            let mut g = lock_inner(&self.inner);
            g.local_ip = Some(ip);
            g.adapter_desc = desc;
            g.engine.set_local_ip(ip);
            g.engine.reset_tracking();
            g.config.network.adapter = ip.to_string();
        }

        if was_running {
            self.start()?;
        }
        self.logger.info(format!("监听网卡已切换为 {}", ip));
        Ok(())
    }

    /// 应用新配置（调用方已完成校验与落盘）。
    pub fn apply_config(&self, cfg: Config) -> Result<()> {
        let whitelist = IpSet::from_rules(&cfg.lists.whitelist)?;
        {
            let mut g = lock_inner(&self.inner);
            g.engine.reload(&cfg);
            g.bans.set_whitelist(whitelist);
            g.config = cfg.clone();
            g.push_event("system", "配置已更新".to_string(), None);
        }
        self.logger.set_level(Level::parse(&cfg.logging.level));
        self.enqueue(Action::SyncSystemRules);
        Ok(())
    }

    /// 最近日志。
    pub fn logs(&self, limit: usize) -> Vec<LogLine> {
        self.logger.tail(limit)
    }
}

/// 启动抓包线程。
fn start_capture(
    inner: &Arc<Mutex<Inner>>,
    tx: &Sender<Action>,
    logger: &Arc<Logger>,
    ip: Ip,
) -> Result<CaptureHandle> {
    let sink = Arc::new(PacketSink {
        inner: Arc::clone(inner),
        tx: tx.clone(),
        logger: Arc::clone(logger),
    });
    let on_packet = {
        let sink = Arc::clone(&sink);
        move |parsed: portguard_packet::ParsedPacket| sink.consume(parsed.info)
    };
    let on_error = {
        let sink = Arc::clone(&sink);
        move |msg: String| sink.on_capture_error(msg)
    };
    capture::start(ip, on_packet, on_error)
}

/// 后台执行线程：串行处理所有慢操作。
fn spawn_worker(
    inner: Arc<Mutex<Inner>>,
    rx: Receiver<Action>,
    firewall: Arc<dyn FirewallBackend>,
    logger: Arc<Logger>,
    paths: AppPaths,
) {
    let builder = std::thread::Builder::new().name("portguard-worker".to_string());
    let spawned = builder.spawn(move || {
        worker_loop(inner, rx, firewall, logger, paths);
    });
    if let Err(e) = spawned {
        // 线程起不来只能降级：此时封停不会真正生效，必须让用户知道。
        // 日志器仍可用（它是独立线程），所以用日志而不是 panic。
        eprintln!("创建执行线程失败：{}", e);
    }
}

fn worker_loop(
    inner: Arc<Mutex<Inner>>,
    rx: Receiver<Action>,
    firewall: Arc<dyn FirewallBackend>,
    logger: Arc<Logger>,
    paths: AppPaths,
) {
    // 启动自检：清理上次异常退出遗留的规则。
    startup_cleanup(&inner, firewall.as_ref(), &logger);

    let mut next_prune = Instant::now() + PRUNE_PASS;
    let mut next_rdp = Instant::now() + RDP_PASS;

    loop {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(action) => apply_action(&inner, &firewall, &logger, &paths, action),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                logger.info("执行线程退出".to_string());
                return;
            }
        }

        let now = Instant::now();
        if now >= next_prune {
            expire_pass(&inner, firewall.as_ref(), &logger, &paths);
            next_prune = now + PRUNE_PASS;
        }
        if now >= next_rdp {
            rdp_pass(&inner, &logger);
            next_rdp = now + RDP_PASS;
        }
    }
}

/// 清理上次遗留的孤儿规则。
fn startup_cleanup(inner: &Arc<Mutex<Inner>>, firewall: &dyn FirewallBackend, logger: &Arc<Logger>) {
    let active = {
        let g = lock_inner(inner);
        g.bans
            .snapshot()
            .iter()
            .map(|r| r.rule_name.clone())
            .collect::<Vec<String>>()
    };
    match cleanup_orphans(firewall, &active) {
        Ok(removed) if !removed.is_empty() => {
            logger.info(format!("已清理 {} 条遗留防火墙规则", removed.len()));
            let mut g = lock_inner(inner);
            g.push_event(
                "system",
                format!("已清理 {} 条遗留防火墙规则", removed.len()),
                None,
            );
        }
        Ok(_) => {}
        Err(e) => logger.warn(format!("遗留规则清理失败：{}", e)),
    }
}

fn apply_action(
    inner: &Arc<Mutex<Inner>>,
    firewall: &Arc<dyn FirewallBackend>,
    logger: &Arc<Logger>,
    paths: &AppPaths,
    action: Action,
) {
    match action {
        Action::Ban(req) => apply_ban(inner, firewall, logger, paths, req),
        Action::Unban(ip) => apply_unban(inner, firewall, logger, ip),
        Action::SyncSystemRules => sync_system_rules(inner, firewall, logger),
    }
}

/// 落地一次封停：先改系统，成功后才更新内存状态（避免状态与系统漂移）。
fn apply_ban(
    inner: &Arc<Mutex<Inner>>,
    firewall: &Arc<dyn FirewallBackend>,
    logger: &Arc<Logger>,
    paths: &AppPaths,
    req: BanRequest,
) {
    let (record, ip_text) = {
        let g = lock_inner(inner);
        // 手动指定 permanent 时临时改写判定依据，不改动真实配置
        let cfg = match req.permanent_override {
            Some(p) => {
                let mut c = g.config.clone();
                c.ban.permanent = p;
                c
            }
            None => g.config.clone(),
        };
        let rec = g.bans.make_record(
            req.ip,
            req.reason,
            &cfg,
            now_ms(),
            req.protocol,
            req.service_port,
            req.remote_port,
            req.attempt_count,
        );
        (rec, req.ip.to_string())
    };

    match firewall.block_ip(req.ip, &record.rule_name) {
        Ok(()) => {
            let mut g = lock_inner(inner);
            g.pending.remove(&u32::from(req.ip));
            if let Err(e) = g.bans.ban(record) {
                // 白名单硬校验拦截（并发场景下白名单可能刚被修改）
                logger.warn(format!("封停被拒绝：{}", e));
                g.push_event("warn", format!("封停被拒绝：{}", e), Some(ip_text));
                return;
            }
            // 封停后从跟踪列表移除，面板立即反映
            g.engine.tracker.remove_ip(u32::from(req.ip));
            g.total_bans = g.total_bans.saturating_add(1);
            let label = g
                .bans
                .get(req.ip)
                .map(|r| r.reason.label().to_string())
                .unwrap_or_default();
            g.push_event(
                "ban",
                format!("已封停 {}（{}）", ip_text, label),
                Some(ip_text.clone()),
            );
            drop(g);

            logger.warn(format!("已封停 {}：{}", ip_text, label));
            persist(inner, paths, logger);
        }
        Err(e) => {
            // 规则没加上，内存中也不能记成已封停（规范 26.1）
            let mut g = lock_inner(inner);
            g.pending.remove(&u32::from(req.ip));
            g.push_event(
                "error",
                format!("封停 {} 失败：{}", ip_text, e),
                Some(ip_text.clone()),
            );
            drop(g);
            logger.error(format!("封停 {} 失败：{}", ip_text, e));
        }
    }
}

/// 落地一次解封。
fn apply_unban(
    inner: &Arc<Mutex<Inner>>,
    firewall: &Arc<dyn FirewallBackend>,
    logger: &Arc<Logger>,
    ip: Ip,
) {
    let rule_name = ban_rule_name(ip);
    let known = { lock_inner(inner).bans.is_banned(ip) };
    if !known {
        return;
    }
    match firewall.delete_rule(&rule_name) {
        Ok(()) => {
            let mut g = lock_inner(inner);
            g.bans.unban(ip);
            g.push_event("unban", format!("已解封 {}", ip), Some(ip.to_string()));
            drop(g);
            logger.info(format!("已解封 {}", ip));
        }
        Err(e) => {
            // 系统里还留着规则，内存状态保持不变，让用户看到真实差异
            let mut g = lock_inner(inner);
            g.push_event(
                "error",
                format!("解封 {} 失败：{}", ip, e),
                Some(ip.to_string()),
            );
            drop(g);
            logger.error(format!("解封 {} 失败：{}", ip, e));
        }
    }
}

/// 定期处理到期封停与跟踪表清理。
fn expire_pass(
    inner: &Arc<Mutex<Inner>>,
    firewall: &dyn FirewallBackend,
    logger: &Arc<Logger>,
    paths: &AppPaths,
) {
    let now = now_ms();
    let (expired, changed) = {
        let mut g = lock_inner(inner);
        let expired = g.bans.take_expired(now);
        g.engine.prune(now, TRACK_RETENTION_MS);
        let changed = !expired.is_empty();
        (expired, changed)
    };

    for ip in expired {
        let rule_name = ban_rule_name(ip);
        match firewall.delete_rule(&rule_name) {
            Ok(()) => {
                let mut g = lock_inner(inner);
                g.bans.unban(ip);
                g.push_event("unban", format!("封停到期，已解封 {}", ip), Some(ip.to_string()));
                logger.info(format!("封停到期，已解封 {}", ip));
            }
            Err(e) => {
                let mut g = lock_inner(inner);
                g.push_event(
                    "error",
                    format!("封停到期但规则删除失败 {}：{}", ip, e),
                    Some(ip.to_string()),
                );
                logger.error(format!("封停到期但规则删除失败 {}：{}", ip, e));
            }
        }
    }
    if changed {
        persist(inner, paths, logger);
    }
}

/// RDP 客户端白名单巡检。
fn rdp_pass(inner: &Arc<Mutex<Inner>>, logger: &Arc<Logger>) {
    let cfg = {
        let g = lock_inner(inner);
        if !g.config.rdp.enabled {
            return;
        }
        g.config.rdp.clone()
    };

    let report = match rdp_policy::run_once(&cfg) {
        Ok(r) => r,
        Err(e) => {
            logger.debug(format!("RDP 巡检跳过：{}", e));
            return;
        }
    };
    if !report.has_action() {
        return;
    }

    let mut g = lock_inner(inner);
    g.push_event(
        "rdp",
        format!(
            "RDP 保护：扫描 {} 个会话，断开 {} 个，失败 {} 个",
            report.scanned,
            report.disconnected.len(),
            report.failures.len()
        ),
        None,
    );
}

/// 应用系统级保护开关（危险端口、禁 Ping）。
fn sync_system_rules(
    inner: &Arc<Mutex<Inner>>,
    firewall: &Arc<dyn FirewallBackend>,
    logger: &Arc<Logger>,
) {
    let cfg = lock_inner(inner).config.clone();

    let result = (|| -> Result<()> {
        if cfg.system.risky_ports {
            let ports = portguard_firewall::backend::RISKY_PORTS;
            firewall.block_ports(
                Protocol::Tcp,
                ports,
                portguard_firewall::backend::RULE_RISKY_TCP,
                RuleDirection::In,
            )?;
            firewall.block_ports(
                Protocol::Udp,
                ports,
                portguard_firewall::backend::RULE_RISKY_UDP,
                RuleDirection::In,
            )?;
        } else {
            for name in [
                portguard_firewall::backend::RULE_RISKY_TCP,
                portguard_firewall::backend::RULE_RISKY_UDP,
            ] {
                let _ = firewall.delete_rule(name);
            }
        }
        firewall.set_block_icmp(cfg.system.block_icmp, cfg.system.block_icmp)?;
        Ok(())
    })();

    match result {
        Ok(()) => {
            let mut g = lock_inner(inner);
            g.push_event("system", "系统保护规则已同步".to_string(), None);
        }
        Err(e) => {
            logger.error(format!("系统保护规则同步失败：{}", e));
            let mut g = lock_inner(inner);
            g.push_event("error", format!("系统保护规则同步失败：{}", e), None);
        }
    }
}

/// 写入封停记录（失败只记日志，不影响封停本身已经生效的事实）。
fn persist(inner: &Arc<Mutex<Inner>>, paths: &AppPaths, logger: &Arc<Logger>) {
    let records = { lock_inner(inner).bans.snapshot() };
    if let Err(e) = BanStore::new(records).save(&paths.bans_file()) {
        logger.error(format!("封停记录写入失败：{}", e));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portguard_core::engine::{FLAG_SYN, Outcome};
    use portguard_firewall::MockFirewall;

    fn temp_paths() -> AppPaths {
        let dir = std::env::temp_dir().join(format!(
            "pg_app_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        AppPaths::with_root(dir)
    }

    fn runtime_with(cfg: Config) -> (RuntimeHandle, Arc<MockFirewall>, AppPaths) {
        let paths = temp_paths();
        let fw = Arc::new(MockFirewall::new());
        let logger = Arc::new(
            Logger::start(&paths.log_file(), Level::Error, 64).expect("创建测试日志器失败"),
        );
        let handle = RuntimeHandle::new(cfg, logger, fw.clone(), paths.clone());
        (handle, fw, paths)
    }

    fn syn_packet(src: &str, local: &str, port: u16) -> PacketInfo {
        PacketInfo {
            src: src.parse().unwrap(),
            dst: local.parse().unwrap(),
            src_port: 40000,
            dst_port: port,
            protocol: Protocol::Tcp,
            tcp_flags: FLAG_SYN,
            length: 40,
            timestamp_ms: 0,
        }
    }

    #[test]
    fn 单个实例只发放一次封停动作() {
        let mut cfg = Config::with_defaults();
        cfg.protect.tcp.max_attempts = 1;
        cfg.network.adapter = "192.168.1.10".to_string();
        let (rt, _, _) = runtime_with(cfg);

        let sink = PacketSink {
            inner: Arc::clone(&rt.inner),
            tx: rt.tx.clone(),
            logger: Arc::clone(&rt.logger),
        };
        // 连续 5 个包：第 2 个就应触发封停，之后因 pending 去重不再重复排队
        for _ in 0..5 {
            sink.consume(syn_packet("203.0.113.9", "192.168.1.10", 3389));
        }
        let pending = rt.read(|i| i.pending.len());
        assert_eq!(pending, 1, "同一来源不应重复入队");
    }

    #[test]
    fn 白名单不产生封停动作() {
        let mut cfg = Config::with_defaults();
        cfg.protect.tcp.max_attempts = 1;
        cfg.network.adapter = "192.168.1.10".to_string();
        cfg.lists.whitelist = vec!["203.0.113.9".to_string()];
        let (rt, _, _) = runtime_with(cfg);

        let sink = PacketSink {
            inner: Arc::clone(&rt.inner),
            tx: rt.tx.clone(),
            logger: Arc::clone(&rt.logger),
        };
        for _ in 0..10 {
            sink.consume(syn_packet("203.0.113.9", "192.168.1.10", 3389));
        }
        assert_eq!(rt.read(|i| i.pending.len()), 0);
    }

    #[test]
    fn 抓包出错会写入事件流() {
        let (rt, _, _) = runtime_with(Config::with_defaults());
        let sink = PacketSink {
            inner: Arc::clone(&rt.inner),
            tx: rt.tx.clone(),
            logger: Arc::clone(&rt.logger),
        };
        sink.on_capture_error("测试错误".to_string());
        let events = rt.read(|i| i.events.iter().map(|e| e.kind.clone()).collect::<Vec<_>>());
        assert_eq!(events.first().map(|s| s.as_str()), Some("error"));
    }

    #[test]
    fn 未选择网卡时启动会明确报错() {
        let (rt, _, _) = runtime_with(Config::with_defaults());
        let err = rt.start().unwrap_err();
        assert!(err.to_string().contains("网卡"));
    }

    #[test]
    fn 阈值封停原因与分组对应() {
        assert_eq!(
            reason_of(&Outcome::ThresholdBan {
                group: PortGroup::Web,
                count: 3,
                threshold: 2
            }),
            BanReason::WebThreshold
        );
        assert_eq!(reason_of(&Outcome::BlacklistBan), BanReason::Blacklist);
        assert_eq!(
            attempt_count_of(&Outcome::ThresholdBan {
                group: PortGroup::Udp,
                count: 9,
                threshold: 1
            }),
            9
        );
    }

    #[test]
    fn 事件流不会无限增长() {
        let (rt, _, _) = runtime_with(Config::with_defaults());
        rt.write(|inner| {
            for i in 0..(MAX_EVENTS + 50) {
                inner.push_event("test", format!("事件 {}", i), None);
            }
        });
        let (len, newest) = rt.read(|inner| {
            (
                inner.events.len(),
                inner.events.front().map(|e| e.message.clone()),
            )
        });
        assert_eq!(len, MAX_EVENTS);
        // 最新的留在队首，最旧的被丢弃
        assert_eq!(newest.unwrap(), format!("事件 {}", MAX_EVENTS + 49));
    }
}
