//! PortGuard 主程序。
//!
//! 形态：托盘 + 内嵌 Web 控制面板（单 exe 部署）。
//!
//! 启动顺序：
//!
//! ```text
//! 参数 → （--service：进入 Windows 服务分发）
//!      → 隐藏控制台窗口 → 数据目录 → 配置 → 日志 → 旧配置迁移 → 单实例 → 权限提示
//!      → 运行时（抓包 + 封停）→ 面板 → 托盘 → 自动选网卡 → 开始保护
//!      → 消息循环（托盘 / Ctrl+C）→ 收尾
//! ```
//!
//! 控制台窗口默认隐藏（`--console` 或从 cmd 启动时保留）：任务栏只留托盘图标，
//! 右键菜单仍可打开面板 / 暂停保护 / 退出；启动期的致命错误改用对话框提示。

// 非测试代码禁止 unwrap/expect（规范 26：失败必须显式处理）。
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
// 可执行文件固定叫 PortGuard.exe（用户与计划任务都按此名引用），
// 与 Rust 的蛇形命名约定冲突，这里明确豁免。
#![allow(non_snake_case)]

mod cli;
mod controller;
mod runtime;

use std::sync::Arc;
use std::time::{Duration, Instant};

use portguard_core::api::PortGuardApi;
use portguard_core::config::Config;
use portguard_core::logging::Level;
use portguard_storage::{AppPaths, ConfigStore, Logger};
use portguard_web::{PanelMeta, WebServer};

use controller::Controller;
use runtime::RuntimeHandle;

/// 托盘与菜单状态刷新间隔。
const UI_REFRESH: Duration = Duration::from_secs(1);

/// 面板端口被占用时最多向后尝试的次数。
const PORT_FALLBACK_TRIES: u16 = 10;

fn main() {
    portguard_win::enable_utf8_output();
    std::process::exit(run());
}

fn run() -> i32 {
    // ---- 参数 ----
    let opts = match cli::parse(std::env::args().skip(1)) {
        Ok(cli::Parsed::Run(o)) => o,
        Ok(cli::Parsed::Print(text)) => {
            println!("{}", text);
            return 0;
        }
        Err(e) => {
            eprintln!("{}", e);
            return 2;
        }
    };

    // ---- 服务分发 ----
    // 必须抢在读配置、抢单实例之前：SCM 只给 30 秒等 StartServiceCtrlDispatcherW，
    // 而这段启动流程里「已有实例在运行」等分支会提前返回，一旦落在分发之前，
    // 用户看到的就是「1053 服务没有及时响应启动或控制请求」。
    if opts.service {
        return match portguard_win::Service::run(move || run_app(opts)) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("服务模式启动失败：{}", e);
                1
            }
        };
    }

    run_app(opts)
}

/// 程序主体。服务模式下来自 SCM 的服务线程，其余情况来自主线程。
fn run_app(opts: cli::Options) -> i32 {
    // ---- 控制台窗口 ----
    // 越早越好：窗口创建到隐藏之间的这段时间是用户唯一会看到黑窗口的时刻。
    let console_hidden = !opts.console && portguard_win::hide_own_console_window();

    // ---- 数据目录与配置 ----
    let paths = match &opts.data_dir {
        Some(dir) => AppPaths::with_root(dir.clone()),
        None => AppPaths::resolve(),
    };
    if let Err(e) = paths.ensure() {
        return fail(&format!("数据目录不可用：{}", e), console_hidden, 1);
    }

    let store = ConfigStore::new(paths.config_file());
    let (mut cfg, outcome) = match store.load_or_create() {
        Ok(v) => v,
        Err(e) => {
            return fail(&format!("配置读取失败：{}", e), console_hidden, 1);
        }
    };

    // ---- 日志 ----
    let logger = match Logger::start(
        &paths.log_file(),
        Level::parse(&cfg.logging.level),
        cfg.logging.max_memory_lines,
    ) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            return fail(&format!("日志初始化失败：{}", e), console_hidden, 1);
        }
    };
    logger.info(format!("PortGuard {} 启动", cli::VERSION));
    if outcome.is_recovery() {
        logger.warn(outcome.describe());
    }

    // ---- 旧配置迁移 ----
    // 迁移结果必须落盘：只改内存的话，第二个实例会照着文件里的旧端口去开面板，
    // 而正在运行的实例已经换到新端口，用户看到的就是「页面打不开」。
    // 写盘失败只告警不退出 —— 迁移本身已经生效，程序照常可用。
    let migrations = cfg.migrate();
    if !migrations.is_empty() {
        if let Err(e) = store.save(&cfg) {
            logger.warn(format!("配置迁移结果写盘失败（本次运行仍然生效）：{}", e));
        }
        for note in migrations {
            logger.info(format!("配置迁移：{}", note));
        }
    }

    // ---- 单实例 ----
    let _guard = match portguard_win::SingleInstance::acquire() {
        Ok(g) => g,
        Err(_) => {
            // 服务模式跑在会话 0，没有交互桌面，开浏览器只会失败刷日志。
            if !opts.service {
                println!("PortGuard 已在运行，正在为你打开现有控制面板…");
                open_panel(&cfg, &logger);
            } else {
                logger.info("已有 PortGuard 实例在运行，本次服务启动退出".to_string());
            }
            return 0;
        }
    };

    if opts.open_only {
        open_panel(&cfg, &logger);
        return 0;
    }

    // 需要在托盘上向用户交代的启动期告警（控制台隐藏时那是唯一的送达渠道）
    let mut notices: Vec<(&str, String)> = Vec::new();

    // ---- 权限 ----
    let admin = portguard_win::is_elevated();
    if !admin {
        let tip = "当前不是管理员权限：抓包与防火墙封停都无法生效，请右键以管理员身份运行";
        logger.error(tip.to_string());
        println!("\n[警告] {}\n", tip);
        notices.push(("需要管理员权限", tip.to_string()));
    }

    let _ = portguard_win::install_exit_handler();

    // ---- 运行时 ----
    let firewall = portguard_firewall::default_backend();
    logger.info(format!("防火墙后端：{}", firewall.name()));
    let rt = Arc::new(RuntimeHandle::new(
        cfg.clone(),
        Arc::clone(&logger),
        firewall,
        paths.clone(),
    ));
    let controller = Arc::new(Controller::new(
        Arc::clone(&rt),
        paths.clone(),
        Arc::clone(&logger),
    ));

    // ---- 网卡 ----
    if !ensure_adapter(&controller, &logger) {
        logger.warn("没有可用的物理网卡，程序将只提供控制面板".to_string());
    }
    cfg = controller.config();

    // ---- 控制面板 ----
    let api: Arc<dyn PortGuardApi> = controller.clone();
    let meta = PanelMeta {
        version: cli::VERSION.to_string(),
        log_file: paths.log_file().display().to_string(),
        // 面板展示的是配置/封停/日志所在的根目录，不是给 IP 库预留的 data/ 子目录
        data_dir: paths.root().display().to_string(),
        started_at_ms: rt.started_at_ms(),
    };
    let mut server = if opts.panel && cfg.panel.enabled {
        start_panel(api, meta, &cfg, Arc::clone(&logger))
    } else {
        logger.info("控制面板已按配置关闭".to_string());
        None
    };

    // ---- 托盘 ----
    // 服务模式由计划任务以 SYSTEM 身份在会话 0 启动，没有交互桌面，
    // 此时创建托盘图标既无意义也可能失败，直接跳过。
    let mut tray = if opts.service {
        logger.info("服务模式：不创建托盘图标".to_string());
        None
    } else {
        match portguard_win::Tray::create("PortGuard", Some(portguard_win::TRAY_ICON)) {
            Ok(t) => Some(t),
            Err(e) => {
                logger.warn(format!("托盘图标创建失败，可用 Ctrl+C 退出：{}", e));
                None
            }
        }
    };

    // ---- 开始保护 ----
    // 规范 23：非管理员时原始套接字与防火墙都不可用，直接不启动，
    // 而不是启动后立刻失败（否则用户看到的是一串无从下手的报错）。
    if opts.auto_start {
        if !admin {
            logger.warn("非管理员权限，已跳过自动开始保护".to_string());
            println!("[提示] 未开始保护：请右键以管理员身份重新运行 PortGuard。\n");
        } else if let Err(e) = controller.start() {
            logger.error(format!("自动开始保护失败：{}", e));
            println!("[警告] 自动开始保护失败：{}", e);
            notices.push(("自动开始保护失败", e.to_string()));
        }
    }

    // 控制台隐藏后，上面这些告警在终端里看不见，改用托盘气泡再送一次；
    // 服务模式（会话 0）没有托盘，只能靠日志与面板呈现。
    if console_hidden {
        if let Some(t) = tray.as_mut() {
            for (title, text) in &notices {
                t.balloon(title, text);
            }
        }
    }

    let panel_url = server
        .as_ref()
        .map(|s| portguard_win::panel_url(s.addr()))
        .unwrap_or_default();

    // 自动打开浏览器（可由配置关闭；服务模式下无人盯着桌面，一律不打开）
    if should_open_browser(&cfg, opts.service, &panel_url) {
        if let Err(e) = portguard_win::open_url(&panel_url) {
            logger.warn(format!("自动打开浏览器失败：{}", e));
        }
    }

    print_banner(&panel_url, &paths.root().display().to_string(), admin);

    // ---- 主循环 ----
    let mut last_refresh = Instant::now() - UI_REFRESH;
    'main: while !portguard_win::exit_requested() {
        let mut actions = Vec::new();
        match tray.as_mut() {
            Some(t) => actions.extend(t.pump(200)),
            None => std::thread::sleep(Duration::from_millis(200)),
        }

        for action in actions {
            match action {
                portguard_win::TrayAction::OpenPanel => {
                    if panel_url.is_empty() {
                        logger.warn("控制面板未启动，无法打开".to_string());
                    } else if let Err(e) = portguard_win::open_url(&panel_url) {
                        logger.warn(format!("打开浏览器失败：{}", e));
                    }
                }
                portguard_win::TrayAction::ToggleProtection => {
                    let running = controller.status().running;
                    let result = if running {
                        controller.stop()
                    } else {
                        controller.start()
                    };
                    if let Err(e) = result {
                        logger.error(format!("切换保护状态失败：{}", e));
                    }
                }
                portguard_win::TrayAction::Exit => {
                    logger.info("收到托盘退出请求".to_string());
                    break 'main;
                }
            }
        }

        // 托盘提示与菜单状态按秒刷新，避免频繁加锁
        if last_refresh.elapsed() >= UI_REFRESH {
            last_refresh = Instant::now();
            if let Some(t) = tray.as_mut() {
                let status = controller.status();
                t.set_menu_state(status.running, status.stats.banned as usize);
                t.set_tooltip(&format!(
                    "PortGuard —— {}，已封停 {}",
                    if status.running { "保护中" } else { "已停止" },
                    status.stats.banned
                ));
            }
        }
    }

    // ---- 收尾 ----
    if let Some(mut s) = server.take() {
        s.stop();
    }
    rt.stop();
    rt.persist_bans();
    drop(tray);
    logger.info("PortGuard 已退出".to_string());
    0
}

/// 启动期致命错误的汇报方式。
///
/// 控制台窗口可见时打印即可；已隐藏时必须弹对话框 —— 否则用户看到的现象是
/// 「双击了，什么都没发生」（规范 26.1：失败不得静默）。
fn fail(message: &str, console_hidden: bool, code: i32) -> i32 {
    if console_hidden {
        portguard_win::show_error("PortGuard 启动失败", message);
    } else {
        eprintln!("{}", message);
    }
    code
}

/// 启动控制面板；端口被占用时自动向后顺延，保证程序总能起来。
fn start_panel(
    api: Arc<dyn PortGuardApi>,
    meta: PanelMeta,
    cfg: &Config,
    logger: Arc<Logger>,
) -> Option<WebServer> {
    let base_port = match cfg.panel.bind.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()) {
        Some(p) => p,
        None => {
            logger.error(format!("面板监听地址不合法：{}", cfg.panel.bind));
            return None;
        }
    };
    let host = cfg
        .panel
        .bind
        .rsplit_once(':')
        .map(|(h, _)| h.to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());

    for offset in 0..PORT_FALLBACK_TRIES {
        let bind = format!("{}:{}", host, base_port.saturating_add(offset));
        match WebServer::start(Arc::clone(&api), meta.clone(), &bind, Arc::clone(&logger)) {
            Ok(server) => {
                if offset > 0 {
                    logger.warn(format!("原端口被占用，控制面板改用 {}", bind));
                }
                return Some(server);
            }
            Err(e) => {
                if offset == 0 {
                    logger.warn(e.to_string());
                }
            }
        }
    }
    logger.error(format!(
        "控制面板启动失败：{}-{} 端口均不可用",
        base_port,
        base_port.saturating_add(PORT_FALLBACK_TRIES - 1)
    ));
    None
}

/// 确保有一个可用的监听网卡；必要时自动挑选一个。
///
/// 挑选优先级：物理网卡 > 虚拟网卡，真实地址 > APIPA 自动私有地址（169.254.x.x）。
/// 返回是否已确定网卡。
fn ensure_adapter(controller: &Controller, logger: &Arc<Logger>) -> bool {
    let cfg = controller.config();
    if portguard_core::iprange::parse_ipv4(&cfg.network.adapter).is_ok() {
        return true;
    }

    let list = match portguard_packet::enumerate(cfg.network.include_virtual) {
        Ok(l) => l,
        Err(e) => {
            logger.warn(format!("网卡枚举失败：{}", e));
            return false;
        }
    };

    let picked = list
        .iter()
        .filter(|a| a.is_usable())
        .min_by_key(|a| (a.is_virtual, a.is_link_local()));

    match picked {
        Some(a) => {
            if let Err(e) = controller.select_adapter(&a.ip.to_string()) {
                logger.warn(format!("自动选择网卡失败：{}", e));
                return false;
            }
            logger.info(format!("已自动选择网卡 {}（{}）", a.ip, a.description));
            if a.is_link_local() {
                logger.warn(
                    "仅找到 169.254.x.x 自动私有地址的网卡，该网卡可能没有实际网络流量".to_string(),
                );
            }
            true
        }
        None => {
            logger.warn("未找到可用网卡，请在控制面板中手动选择".to_string());
            false
        }
    }
}

/// 是否应当自动打开浏览器。
///
/// 三个条件缺一不可：用户在配置里开着该选项、不是服务模式（服务模式没有交互桌面）、
/// 面板确实已启动（否则会打开一个打不开的地址）。
fn should_open_browser(cfg: &Config, service_mode: bool, panel_url: &str) -> bool {
    cfg.panel.auto_open_browser && !service_mode && !panel_url.is_empty()
}

/// 用默认浏览器打开控制面板。
fn open_panel(cfg: &Config, logger: &Arc<Logger>) {
    let url = portguard_win::panel_url(&cfg.panel.bind);
    match portguard_win::open_url(&url) {
        Ok(()) => println!("控制面板：{}", url),
        Err(e) => {
            logger.warn(format!("打开浏览器失败：{}", e));
            println!("请在浏览器中访问：{}", url);
        }
    }
}

/// 控制台启动横幅。
fn print_banner(panel_url: &str, data_dir: &str, admin: bool) {
    println!();
    println!("  PortGuard {} —— 恶意连接识别与自动封停", cli::VERSION);
    println!("  ─────────────────────────────────────────────");
    if panel_url.is_empty() {
        println!("  控制面板：未启动");
    } else {
        println!("  控制面板：{}", panel_url);
    }
    println!("  数据目录：{}", data_dir);
    println!(
        "  运行权限：{}",
        if admin { "管理员" } else { "普通用户（功能受限）" }
    );
    println!("  退出方式：托盘右键退出，或按 Ctrl+C");
    println!("  提示：加 --console 启动可保留本窗口，便于排查问题");
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 面板地址解析支持主机与端口() {
        let mut cfg = Config::with_defaults();
        cfg.panel.bind = "127.0.0.1:18999".to_string();
        let host = cfg
            .panel
            .bind
            .rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_default();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(
            cfg.panel.bind.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()),
            Some(18999)
        );
    }

    #[test]
    fn 自动打开浏览器受三条件约束() {
        let cfg = Config::with_defaults();
        assert!(cfg.panel.auto_open_browser, "默认应自动打开");
        assert!(should_open_browser(&cfg, false, "http://127.0.0.1:58080"));

        // 服务模式一律不打开
        assert!(!should_open_browser(&cfg, true, "http://127.0.0.1:58080"));

        // 面板未启动时不打开
        assert!(!should_open_browser(&cfg, false, ""));

        // 用户在配置里关掉后不打开
        let mut off = Config::with_defaults();
        off.panel.auto_open_browser = false;
        assert!(!should_open_browser(&off, false, "http://127.0.0.1:58080"));
    }

    #[test]
    fn 非法端口不会导致恐慌() {
        let bind = "127.0.0.1:不是端口";
        assert!(bind.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()).is_none());
    }
}
