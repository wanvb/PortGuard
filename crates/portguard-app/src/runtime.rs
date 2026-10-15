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
use portguard_core::model::{BanReason, FlagClass, Ip, PacketInfo, PortGroup, Protocol};
use portguard_core::observe::Observer;
use portguard_core::time::now_ms;
use portguard_firewall::{cleanup_orphans, FirewallBackend, RuleDirection};
use portguard_packet::{capture, CaptureDiagnostics, CaptureHandle};
use portguard_rdp::policy as rdp_policy;
use portguard_storage::{AppPaths, BanStore, Logger};

/// 面板连接列表的回看窗口：超过该时长未再出现的条目不再展示。
const CONNECTION_TTL_MS: u64 = 5 * 60 * 1000;

/// 事件流保留条数。
const MAX_EVENTS: usize = 200;

/// 跟踪表清理周期与保留时长。
///
/// 保留期同时是**累计计数的归零线**：判定按累计连接次数进行（不做滑动窗口），
/// 某来源连续空闲超过保留期后条目被回收，下次出现时从 0 重新计数。
const PRUNE_PASS: Duration = Duration::from_secs(5);
const TRACK_RETENTION_MS: u64 = 10 * 60 * 1000;

/// RDP 巡检的最小间隔（避免高频枚举会话）。
const RDP_PASS: Duration = Duration::from_secs(15);

/// 保护端口全空时的启动告警文案。
const EMPTY_PROTECT_WARNING: &str =
    "保护端口为空：不会统计任何连接、也不会自动封停，请在设置页填写保护端口";

/// 面板「抓包观测」展示的条数上限。
pub const OBSERVE_TOP_LIMIT: usize = 12;

/// 自动切换连接事件来源时的说明文案（会进日志与事件流）。
const AUTO_ACCEPT_NOTICE: &str = "该网卡收不到入站 SYN（混杂模式只看到本机发出的包），\
已自动改用本机发出的握手响应（SYN+ACK）统计连接事件，可在设置页关闭";

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
    /// 抓包观测表：记录「实际收到了什么」，纯诊断，不参与判定。
    ///
    /// 存在的理由是回答「端口完全没反应」这一类问题：没有它就只能靠猜，
    /// 分不清「没抓到」「抓到但标志不对」「抓到但被判定层丢掉」三种情况。
    pub observer: Observer,
    /// 是否已经就「连接事件来源」做过一次自动判定（含用户显式设置）。
    accept_decided: bool,
    /// 是否由运行期自动启用了「统计服务端应答」。
    auto_accept: bool,
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
        // 观测必须发生在判定之前：即使这个包马上会被判定层丢掉，
        // 也要能在面板上看到「它确实到过这里」，否则无从区分丢在哪一层。
        g.observer.observe(&pkt, local_ip);
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

    /// 抓包层诊断（解析失败计数与样本）；未启动时返回全零。
    pub fn capture_diagnostics(&self) -> CaptureDiagnostics {
        self.capture
            .as_ref()
            .map(|c| c.diagnostics())
            .unwrap_or_default()
    }

    /// 当前生效的连接事件来源：是否把服务端握手响应当作一次连接事件。
    pub fn count_accept(&self) -> bool {
        self.engine.count_accept()
    }

    /// 根据配置与自动判定结果重算「连接事件来源」。
    fn apply_accept_mode(&mut self, requested: bool) {
        self.engine.set_count_accept(requested || self.auto_accept);
    }

    /// 重开抓包或换网卡后，旧的观测数据不再代表当前网卡。
    fn reset_observer(&mut self, redetect: bool) {
        self.observer.clear();
        // 换网卡要重新观测：新网卡的混杂模式行为可能完全不同。
        // 但只针对「运行期自己判定出来的」结果重来，用户显式设置过就不再自动覆盖。
        if redetect && self.auto_accept {
            self.accept_decided = false;
            self.auto_accept = false;
            let requested = self.config.protect.count_accept;
            self.apply_accept_mode(requested);
        }
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
                    count: row.count,
                    first_seen_ms: row.first_seen_ms,
                    last_seen_ms: row.last_seen_ms,
                    threshold: rule.max_attempts,
                    state: state.to_string(),
                    whitelisted,
                    // 地理位置与备注都由控制面板层填充：这一层只产出判定数据（规范 22）
                    location: String::new(),
                    port_note: String::new(),
                    ip_note: String::new(),
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

        let protect_empty = !config.has_any_protected_port();
        // 配置里已经把「统计服务端应答」写成开或关，都视作用户的决定。
        let accept_decided = config.protect.count_accept;

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
            observer: Observer::new(),
            accept_decided,
            auto_accept: false,
            pending: HashSet::new(),
        }));

        // 保护端口全空时程序「看着在跑」却不会统计、也不会封停任何端口。
        // 启动即告警并写入事件流，避免用户对着一片空白的连接列表无从下手。
        if protect_empty {
            logger.warn(EMPTY_PROTECT_WARNING.to_string());
            let mut g = lock_inner(&inner);
            g.push_event("warn", EMPTY_PROTECT_WARNING.to_string(), None);
        }

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

    /// 数据目录（配置、封停记录、日志所在的根目录）。
    ///
    /// 注意不是 `AppPaths::data_dir()`——那是给 IP 地理位置库预留的 `data/` 子目录，
    /// 拿它当「数据目录」展示会让用户去空目录里找 `config.toml`。
    pub fn data_dir(&self) -> String {
        self.paths.root().display().to_string()
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
        // 每次重新开始抓包都从头观测，避免拿停止期间的旧数据做判断。
        g.reset_observer(false);
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
            g.reset_observer(true);
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
            // 用户显式改过「统计服务端应答」就不再自动覆盖，否则用户在设置页
            // 关掉它以后会被运行期判定重新打开，看起来像设置没生效。
            if cfg.protect.count_accept != g.config.protect.count_accept {
                g.accept_decided = true;
                g.auto_accept = false;
            }
            g.engine.reload(&cfg);
            g.bans.set_whitelist(whitelist);
            g.config = cfg.clone();
            g.apply_accept_mode(cfg.protect.count_accept);
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
            accept_pass(&inner, &logger);
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
            // 保留跟踪行（状态显示为 BANNED / PERMANENT），不在这里删除：
            // 删掉后用户只看得到「封停记录」，看不到这个 IP 究竟在打哪个端口、
            // 打了几次；行本身仍按 TTL 过期，不会永久占用面板。
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

/// 自动判定「连接事件来源」，解决本机收不到入站 SYN 的问题。
///
/// 背景：混杂模式（`SIO_RCVALL`）在部分云主机 / 网卡上只能看到**本机发出**的包，
/// 入站方向的包一个都收不到（同类工具的原程序正是因此改用 SYN+ACK 累计）。
/// 此时若只认入站 `SYN`，无论客户端怎么连都不会产生任何记录。
///
/// 判定必须同时满足，缺一不做切换：
/// - 受保护的 TCP 端口上，入站纯 `SYN` 一条都没有；
/// - 同一个端口上已经出现本机发出的 `SYN+ACK`（只有真的有人连进来才会有）。
///
/// 该判定只做一次；用户显式改过设置（`accept_decided`）后永不自动覆盖。
fn accept_pass(inner: &Arc<Mutex<Inner>>, logger: &Arc<Logger>) {
    let mut g = lock_inner(inner);
    if g.accept_decided || g.auto_accept {
        return;
    }
    let ports: HashSet<u16> = g
        .config
        .protect
        .tcp
        .ports
        .iter()
        .chain(g.config.protect.http.ports.iter())
        .copied()
        .collect();
    if ports.is_empty() {
        // 没有受保护的 TCP 端口，观察不出结论，等配置补上再说。
        return;
    }

    let inbound_syn = g.observer.count_matching(|o| {
        o.inbound && o.protocol == Protocol::Tcp && o.flags == FlagClass::Syn && ports.contains(&o.port)
    });
    if inbound_syn > 0 {
        // 入站可见，规范 4.1 的原始口径就是对的，不再自动干预。
        g.accept_decided = true;
        return;
    }
    let outbound_syn_ack = g.observer.count_matching(|o| {
        !o.inbound
            && o.protocol == Protocol::Tcp
            && o.flags == FlagClass::SynAck
            && ports.contains(&o.port)
    });
    if outbound_syn_ack == 0 {
        // 还没有任何证据，继续观察（用户可能只是还没连过）。
        return;
    }

    g.auto_accept = true;
    g.accept_decided = true;
    g.apply_accept_mode(false);
    g.push_event("warn", AUTO_ACCEPT_NOTICE.to_string(), None);
    drop(g);
    logger.warn(AUTO_ACCEPT_NOTICE.to_string());
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

    /// 默认配置 + 入站 SYN 口径（关掉默认开启的「统计服务端应答」）。
    ///
    /// 本组用例投递的都是入站 SYN 包，而默认口径已改为握手响应（SYN+ACK），
    /// 不显式关闭就一条都统计不到。
    fn inbound_config() -> Config {
        let mut cfg = Config::with_defaults();
        cfg.protect.count_accept = false;
        cfg
    }

    #[test]
    fn 单个实例只发放一次封停动作() {
        let mut cfg = inbound_config();
        cfg.protect.tcp.max_attempts = 1;
        cfg.network.adapter = "192.168.1.10".to_string();
        let (rt, _, _) = runtime_with(cfg);

        let sink = PacketSink {
            inner: Arc::clone(&rt.inner),
            tx: rt.tx.clone(),
            logger: Arc::clone(&rt.logger),
        };
        // 连续 5 个包：阈值 1，第 1 个就触发封停，之后因 pending 去重不再重复排队
        for _ in 0..5 {
            sink.consume(syn_packet("203.0.113.9", "192.168.1.10", 3389));
        }
        let pending = rt.read(|i| i.pending.len());
        assert_eq!(pending, 1, "同一来源不应重复入队");
    }

    #[test]
    fn 白名单不产生封停动作() {
        let mut cfg = inbound_config();
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
    fn 封停后跟踪行保留并标记状态() {
        let mut cfg = inbound_config();
        // 阈值放宽，先只产生跟踪记录、不触发自动封停（避免与工作线程竞态）
        cfg.protect.tcp.max_attempts = 99;
        cfg.network.adapter = "192.168.1.10".to_string();
        let (rt, fw, paths) = runtime_with(cfg);
        let sink = PacketSink {
            inner: Arc::clone(&rt.inner),
            tx: rt.tx.clone(),
            logger: Arc::clone(&rt.logger),
        };
        for _ in 0..3 {
            sink.consume(syn_packet("203.0.113.9", "192.168.1.10", 3389));
        }

        let fw_dyn: Arc<dyn FirewallBackend> = fw.clone();
        apply_action(
            &rt.inner,
            &fw_dyn,
            &rt.logger,
            &paths,
            Action::Ban(BanRequest {
                ip: "203.0.113.9".parse().unwrap(),
                // 用自动封停原因：手动封停按规范一律永久，得不到 BANNED 状态
                reason: BanReason::TcpThreshold,
                protocol: Some(Protocol::Tcp),
                service_port: Some(3389),
                remote_port: Some(40000),
                attempt_count: 3,
                permanent_override: None,
            }),
        );

        let rows = rt.read(|i| i.connection_rows());
        assert_eq!(rows.len(), 1, "封停后不得删除跟踪行");
        assert_eq!(rows[0].ip, "203.0.113.9");
        assert_eq!(rows[0].service_port, 3389);
        assert_eq!(rows[0].state, "BANNED");
        assert_eq!(rows[0].count, 3);
    }

    #[test]
    fn 保护端口为空时启动会写入告警事件() {
        let mut cfg = Config::with_defaults();
        cfg.protect.tcp.ports.clear();
        cfg.protect.http.ports.clear();
        cfg.protect.udp.ports.clear();
        let (rt, _, _) = runtime_with(cfg);
        let warned = rt.read(|i| {
            i.events
                .iter()
                .any(|e| e.kind == "warn" && e.message.contains("保护端口为空"))
        });
        assert!(warned, "保护端口全空必须显式告警，不得静默失效");
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

    /// 本机发出的握手响应（出站 SYN+ACK）。
    fn syn_ack_packet(peer: &str, local: &str, local_port: u16) -> PacketInfo {
        PacketInfo {
            src: local.parse().unwrap(),
            dst: peer.parse().unwrap(),
            src_port: local_port,
            dst_port: 51000,
            protocol: Protocol::Tcp,
            tcp_flags: portguard_core::model::TcpFlags {
                syn: true,
                ack: true,
                ..Default::default()
            },
            length: 40,
            timestamp_ms: 0,
        }
    }

    fn sink_of(rt: &RuntimeHandle) -> PacketSink {
        PacketSink {
            inner: Arc::clone(&rt.inner),
            tx: rt.tx.clone(),
            logger: Arc::clone(&rt.logger),
        }
    }

    #[test]
    fn 观测表记录被判定层丢弃的包() {
        let mut cfg = Config::with_defaults();
        cfg.network.adapter = "192.168.1.10".to_string();
        let (rt, _, _) = runtime_with(cfg);
        let sink = sink_of(&rt);

        // 8080 不在任何保护组内，判定层必然丢弃它
        sink.consume(syn_packet("203.0.113.9", "192.168.1.10", 8080));

        let rows = rt.read(|i| i.observer.top(10));
        assert_eq!(rows.len(), 1, "被丢弃的包也必须留在观测表里");
        assert_eq!(rows[0].port, 8080);
        assert!(rows[0].inbound);
        assert_eq!(rows[0].count, 1);
        // 判定层确实把它丢掉了（没有产生跟踪行）
        assert_eq!(rt.read(|i| i.engine.tracker.len()), 0);
    }

    #[test]
    fn 入站不可见时自动改用握手响应() {
        // 自动回退只在「配置里是入站口径」时才有意义（默认已开启就不再回退）
        let mut cfg = inbound_config();
        cfg.network.adapter = "192.168.1.10".to_string();
        let (rt, _, _) = runtime_with(cfg);
        let sink = sink_of(&rt);

        // 只有本机发出的 SYN+ACK（入站 SYN 一条都收不到）
        for _ in 0..2 {
            sink.consume(syn_ack_packet("203.0.113.9", "192.168.1.10", 3389));
        }
        accept_pass(&rt.inner, &rt.logger);

        assert!(rt.read(|i| i.count_accept()), "应自动改用握手响应统计");
        assert!(
            rt.read(|i| i.events.iter().any(|e| e.kind == "warn"
                && e.message.contains("入站 SYN"))),
            "自动切换必须在事件流里说明原因"
        );
        // 生效后连接必须真的被跟踪到 3389（切换前的那两个包已被丢弃，不会补记）
        sink.consume(syn_ack_packet("203.0.113.9", "192.168.1.10", 3389));
        let rows = rt.read(|i| i.connection_rows());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].service_port, 3389);
        assert_eq!(rows[0].ip, "203.0.113.9");
    }

    #[test]
    fn 入站可见时不做自动切换() {
        let mut cfg = inbound_config();
        cfg.network.adapter = "192.168.1.10".to_string();
        let (rt, _, _) = runtime_with(cfg);
        let sink = sink_of(&rt);

        sink.consume(syn_packet("203.0.113.9", "192.168.1.10", 3389));
        sink.consume(syn_ack_packet("203.0.113.9", "192.168.1.10", 3389));
        accept_pass(&rt.inner, &rt.logger);

        assert!(!rt.read(|i| i.count_accept()), "入站可见时不得改变事件来源");
    }

    #[test]
    fn 用户显式设置后不再自动改写() {
        let mut cfg = Config::with_defaults();
        cfg.network.adapter = "192.168.1.10".to_string();
        cfg.protect.count_accept = true;
        let (rt, _, _) = runtime_with(cfg.clone());
        // 用户在设置页把它关掉：此后视为已决定，运行期不得再自动打开
        let mut off = cfg.clone();
        off.protect.count_accept = false;
        rt.apply_config(off).unwrap();

        let sink = sink_of(&rt);
        for _ in 0..2 {
            sink.consume(syn_ack_packet("203.0.113.9", "192.168.1.10", 3389));
        }
        // 观测里确实有「出站 SYN+ACK 而无入站 SYN」的证据，否则本用例没有意义
        assert!(rt.read(|i| i.observer.count_matching(|o| {
            !o.inbound && o.flags == FlagClass::SynAck && o.port == 3389
        })) > 0);

        accept_pass(&rt.inner, &rt.logger);
        assert!(!rt.read(|i| i.count_accept()), "不得覆盖用户的显式设置");
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
