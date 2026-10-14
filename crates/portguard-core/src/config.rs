//! 配置模型与 TOML 读写。
//!
//! 相对旧版 `config.dat` 的差异：改为纯文本 `config.toml`，可手工编辑、可版本管理。
//! 旧格式迁移在 `portguard-storage` 中单独实现，本模块只负责新格式。

use crate::error::{AppError, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// 单组保护端口的策略。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProtectionRule {
    /// 受保护的端口列表。
    pub ports: Vec<u16>,
    /// 允许的最大连接次数，**累计**达到该次数即封停。
    ///
    /// 计数不做滑动窗口：只要该来源还在活动就一直累加，空闲超过跟踪保留期
    /// （见 `portguard-app` 的 `TRACK_RETENTION_MS`）后条目被回收、计数归零。
    pub max_attempts: u32,
}

impl Default for ProtectionRule {
    fn default() -> Self {
        ProtectionRule {
            ports: Vec::new(),
            max_attempts: 5,
        }
    }
}

impl ProtectionRule {
    /// 规范化：去重、排序、剔除 0 号端口；并把明显不合理的阈值兜底。
    pub fn normalize(&mut self) {
        self.ports.retain(|p| *p > 0);
        self.ports.sort_unstable();
        self.ports.dedup();
        if self.max_attempts == 0 {
            self.max_attempts = 1;
        }
    }
}

/// 三组保护策略。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProtectConfig {
    /// 普通 TCP 保护端口。
    pub tcp: ProtectionRule,
    /// UDP 保护端口。
    pub udp: ProtectionRule,
    /// TCP-WEB 保护端口（原程序中的 WEB 分类，非硬编码 80/443）。
    pub http: ProtectionRule,
    /// 是否把「服务端握手响应（SYN+ACK）」也当成一次连接事件。
    ///
    /// 默认关闭（规范 4.1 只认入站 `SYN && !ACK`）。但在部分云主机上，
    /// 混杂模式收不到入站包（同类工具的原程序正是因此改用 SYN+ACK 累计），
    /// 打开本项后 TCP 事件改由本机发出的握手响应产生，不再依赖入站可见性。
    /// 运行期发现「入站 SYN 一个都没有、出站 SYN+ACK 却有」时会自动启用并在事件流说明。
    pub count_accept: bool,
}

/// 默认保护端口。
///
/// 必须与配置文件模板保持一致：`#[serde(default)]` 在用户手写的
/// 局部配置（或旧版本升级后新增字段）上走的就是这个默认值，
/// 若这里给空端口，程序会静默失去保护能力。
impl Default for ProtectConfig {
    fn default() -> Self {
        ProtectConfig {
            tcp: ProtectionRule {
                ports: vec![3389],
                max_attempts: 5,
            },
            udp: ProtectionRule {
                ports: vec![3389],
                max_attempts: 5,
            },
            http: ProtectionRule {
                ports: vec![80, 443],
                max_attempts: 10,
            },
            count_accept: false,
        }
    }
}

/// 内置 Web 面板配置。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PanelConfig {
    /// 是否启用面板。
    pub enabled: bool,
    /// 监听地址。默认仅本机回环，避免把「能封 IP 的接口」暴露到网络。
    pub bind: String,
    /// 启动后是否自动打开默认浏览器。
    pub auto_open_browser: bool,
}

/// 面板默认监听地址。
///
/// 结构版本 2 起改用 58080：18080 是各类本地调试工具的常用端口，
/// 冲突概率高（端口顺延虽能救急，但用户按文档访问就会打不开）。
pub const DEFAULT_PANEL_BIND: &str = "127.0.0.1:58080";

/// 结构版本 1 的面板默认监听地址，仅用于升级迁移。
const LEGACY_PANEL_BIND: &str = "127.0.0.1:18080";

impl Default for PanelConfig {
    fn default() -> Self {
        PanelConfig {
            enabled: true,
            bind: DEFAULT_PANEL_BIND.to_string(),
            auto_open_browser: true,
        }
    }
}

/// 网络抓包配置。
///
/// 字段默认值（空网卡 + 不含虚拟网卡）与 `derive(Default)` 一致，故直接派生。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    /// 选定的网卡标识（IP 字符串形式，空表示未选择）。
    pub adapter: String,
    /// 网卡列表中是否包含虚拟网卡。
    pub include_virtual: bool,
}

/// 封停策略配置。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BanConfig {
    /// 临时封停时长（秒）。
    pub duration_seconds: u64,
    /// 是否一律永久封停。
    pub permanent: bool,
}

impl Default for BanConfig {
    fn default() -> Self {
        BanConfig {
            duration_seconds: 3600,
            permanent: false,
        }
    }
}

/// 白名单 / 黑名单原始规则字符串。
///
/// 这里保留字符串而不是解析结果，便于用户在界面上看到自己写的内容；
/// 校验在保存时完成，解析结果由运行期缓存持有。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ListsConfig {
    pub whitelist: Vec<String>,
    pub blacklist: Vec<String>,
}

/// RDP 客户端计算机名保护配置。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RdpConfig {
    pub enabled: bool,
    /// 允许接入的客户端计算机名（不区分大小写）。为空表示不限制。
    pub client_whitelist: Vec<String>,
}

/// 系统级保护开关。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SystemConfig {
    /// 危险端口保护（135/137/138/139/445）。
    pub risky_ports: bool,
    /// 屏蔽 ICMP Echo Request（禁止 Ping）。
    pub block_icmp: bool,
    /// 开机自动启动（计划任务）。
    pub autostart: bool,
}

/// 日志配置。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// 日志级别：trace / debug / info / warn / error。
    pub level: String,
    /// 内存中保留的日志行数上限（供 Web 面板读取）。
    pub max_memory_lines: usize,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        LoggingConfig {
            level: "info".to_string(),
            max_memory_lines: 2000,
        }
    }
}

/// IP 地理位置展示配置。
///
/// 地理位置只用于面板展示，**不参与封停判定**（规范 22）：
/// 数据库文件不随程序分发，缺失或损坏时面板显示「未知」并照常工作。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GeoConfig {
    /// 是否展示来源 IP 的地理位置。
    pub enabled: bool,
    /// 数据库文件名。相对路径先按数据目录 `data/` 查找，再按程序目录查找。
    pub db: String,
}

impl Default for GeoConfig {
    fn default() -> Self {
        GeoConfig {
            enabled: true,
            db: DEFAULT_GEO_DB.to_string(),
        }
    }
}

/// 默认地理位置库文件名。
pub const DEFAULT_GEO_DB: &str = "ip2region_v4.xdb";

/// 顶层配置。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub panel: PanelConfig,
    pub network: NetworkConfig,
    pub protect: ProtectConfig,
    pub ban: BanConfig,
    pub lists: ListsConfig,
    pub rdp: RdpConfig,
    pub system: SystemConfig,
    pub logging: LoggingConfig,
    pub geo: GeoConfig,
    /// 配置结构版本，便于后续迁移。
    pub config_version: u32,
}

/// 与 [`Config::with_defaults`] 同源。
///
/// `#[serde(default)]` 在解析局部配置（用户手写、或旧版本升级后新增字段）时
/// 走的就是这里，两者若不一致，缺失字段会静默变成「空端口 + 版本 0」。
impl Default for Config {
    fn default() -> Self {
        Config::with_defaults()
    }
}

/// 默认配置：与开发文档 13.1 的建议值保持一致。
impl Config {
    pub fn with_defaults() -> Config {
        Config {
            config_version: CURRENT_CONFIG_VERSION,
            panel: PanelConfig::default(),
            network: NetworkConfig::default(),
            protect: ProtectConfig::default(),
            ban: BanConfig::default(),
            lists: ListsConfig::default(),
            rdp: RdpConfig::default(),
            system: SystemConfig::default(),
            logging: LoggingConfig::default(),
            geo: GeoConfig::default(),
        }
    }

    /// 从 TOML 文本解析并规范化。
    pub fn from_toml(text: &str) -> Result<Config> {
        let mut cfg: Config = toml::from_str(text)?;
        cfg.normalize();
        Ok(cfg)
    }

    /// 序列化为 TOML 文本。
    pub fn to_toml(&self) -> Result<String> {
        Ok(toml::to_string_pretty(self)?)
    }

    /// 从文件加载；文件不存在时返回默认配置。
    pub fn load(path: &Path) -> Result<Config> {
        if !path.exists() {
            return Ok(Config::with_defaults());
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| AppError::Config(format!("读取 {} 失败：{}", path.display(), e)))?;
        Config::from_toml(&text)
    }

    /// 保存到文件（自动创建父目录）。
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)
                    .map_err(|e| AppError::Config(format!("创建目录失败：{}", e)))?;
            }
        }
        let text = self.to_toml()?;
        std::fs::write(path, text)
            .map_err(|e| AppError::Config(format!("写入 {} 失败：{}", path.display(), e)))
    }

    /// 规范化所有子结构。
    pub fn normalize(&mut self) {
        self.protect.tcp.normalize();
        self.protect.udp.normalize();
        self.protect.http.normalize();
        if self.ban.duration_seconds == 0 {
            self.ban.duration_seconds = 60;
        }
        if self.panel.bind.trim().is_empty() {
            self.panel.bind = PanelConfig::default().bind;
        }
        if self.logging.max_memory_lines == 0 {
            self.logging.max_memory_lines = 2000;
        }
        if self.geo.db.trim().is_empty() {
            self.geo.db = DEFAULT_GEO_DB.to_string();
        }
        self.lists.whitelist = normalize_rule_lines(&self.lists.whitelist);
        self.lists.blacklist = normalize_rule_lines(&self.lists.blacklist);
        self.rdp.client_whitelist = normalize_rule_lines(&self.rdp.client_whitelist);
        // 旧版配置（或缺失该字段）统一抬到当前结构版本，避免后续迁移误判
        if self.config_version < CURRENT_CONFIG_VERSION {
            self.config_version = CURRENT_CONFIG_VERSION;
        }
    }

    /// 把旧版本留下的默认值迁移到当前默认值，返回每条迁移的中文说明（无迁移则为空）。
    ///
    /// 目前只有一条：面板监听地址 `127.0.0.1:18080` → `127.0.0.1:58080`。
    /// 18080 是各类本地调试工具的常用端口，冲突概率高；凡是仍停在该地址的配置
    /// 一律跟着新默认值走（刻意保留 18080 的写法不再支持，换个端口即可）。
    ///
    /// 与 [`Config::normalize`] 分开是有意为之：迁移只改内存，是否落盘由调用方决定。
    /// 主程序启动时会把迁移结果立即写回配置文件——只改内存的话，第二个实例会拿着
    /// 文件里的旧端口去开面板，而正在运行的实例已经换到新端口了。
    pub fn migrate(&mut self) -> Vec<String> {
        let mut done = Vec::new();
        if self.panel.bind == LEGACY_PANEL_BIND {
            self.panel.bind = PanelConfig::default().bind;
            done.push(format!(
                "面板监听地址 {} → {}（旧端口与其它软件冲突概率高）",
                LEGACY_PANEL_BIND, self.panel.bind
            ));
        }
        done
    }

    /// 校验，返回人类可读的中文错误信息列表。
    pub fn validate(&self) -> Vec<String> {
        let mut errs = Vec::new();
        if let Err(e) = crate::iprange::IpSet::from_rules(&self.lists.whitelist) {
            errs.push(format!("白名单：{}", e));
        }
        if let Err(e) = crate::iprange::IpSet::from_rules(&self.lists.blacklist) {
            errs.push(format!("黑名单：{}", e));
        }
        if self.panel.enabled && self.panel.bind.parse::<std::net::SocketAddr>().is_err() {
            errs.push(format!(
                "面板监听地址非法（应为 IP:端口，如 {}）：{}",
                DEFAULT_PANEL_BIND,
                self.panel.bind
            ));
        }
        // 三组端口全空时程序「看着在跑」却不会统计、也不会封停任何端口，
        // 属于静默失效（规范 26.1），这里直接拒绝保存并给出可操作的提示。
        if !self.has_any_protected_port() {
            errs.push(
                "保护端口为空：TCP / TCP-WEB / UDP 至少填写一个端口，否则不会产生任何连接记录与自动封停"
                    .to_string(),
            );
        }
        errs
    }

    /// 三组保护端口是否至少有一个。
    pub fn has_any_protected_port(&self) -> bool {
        !self.protect.tcp.ports.is_empty()
            || !self.protect.http.ports.is_empty()
            || !self.protect.udp.ports.is_empty()
    }
}

/// 当前配置结构版本号。
///
/// - 1：初版（面板默认端口 `127.0.0.1:18080`）
/// - 2：面板默认端口改为 [`DEFAULT_PANEL_BIND`]（`127.0.0.1:58080`），加载时迁移旧值
pub const CURRENT_CONFIG_VERSION: u32 = 2;

/// 清洗规则行：去空白、去空行、去注释行。
fn normalize_rule_lines(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 默认配置符合文档建议值() {
        let c = Config::with_defaults();
        assert_eq!(c.protect.tcp.ports, vec![3389]);
        assert_eq!(c.protect.http.ports, vec![80, 443]);
        assert_eq!(c.ban.duration_seconds, 3600);
        assert_eq!(c.panel.bind, DEFAULT_PANEL_BIND);
        assert_eq!(c.panel.bind, "127.0.0.1:58080");
        assert!(c.validate().is_empty());
    }

    #[test]
    fn 旧默认面板端口被迁移到新端口() {
        // 手写局部配置
        let mut partial = Config::from_toml("[panel]\nbind = \"127.0.0.1:18080\"\n").unwrap();
        let done = partial.migrate();
        assert_eq!(partial.panel.bind, "127.0.0.1:58080");
        assert_eq!(done.len(), 1, "迁移必须如实上报：{:?}", done);

        // 老版本写下的完整配置（config_version = 1）
        let mut old = Config::from_toml("config_version = 1\n[panel]\nbind = \"127.0.0.1:18080\"\n")
            .unwrap();
        assert!(!old.migrate().is_empty());
        assert_eq!(old.panel.bind, "127.0.0.1:58080");
        old.normalize();
        assert_eq!(old.config_version, CURRENT_CONFIG_VERSION);

        // 用户自己定过的地址一律不动
        let mut custom = Config::from_toml("config_version = 1\n[panel]\nbind = \"127.0.0.1:19000\"\n")
            .unwrap();
        assert!(custom.migrate().is_empty());
        assert_eq!(custom.panel.bind, "127.0.0.1:19000");

        // 迁移幂等：再跑一次无事发生
        assert!(partial.migrate().is_empty());
    }

    #[test]
    fn 配置文本往返一致() {
        let mut c = Config::with_defaults();
        c.lists.whitelist = vec!["192.168.1.*".to_string()];
        c.system.block_icmp = true;
        let text = c.to_toml().unwrap();
        let back = Config::from_toml(&text).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn 空文件解析为默认值() {
        let c = Config::from_toml("").unwrap();
        // 空 TOML 全部字段走 Default，必须与 with_defaults 完全一致，
        // 否则手写局部配置会让程序静默失去保护能力。
        assert_eq!(c, Config::with_defaults());
    }

    #[test]
    fn 只写面板段时保护端口不丢失() {
        let c = Config::from_toml("[panel]\nbind = \"127.0.0.1:19000\"\n").unwrap();
        assert_eq!(c.panel.bind, "127.0.0.1:19000");
        assert_eq!(c.protect.tcp.ports, vec![3389]);
        assert_eq!(c.protect.http.ports, vec![80, 443]);
        assert_eq!(c.protect.udp.ports, vec![3389]);
    }

    #[test]
    fn 部分字段配置可解析() {
        let c = Config::from_toml("[protect.tcp]\nports = [22, 3389]\n").unwrap();
        assert_eq!(c.protect.tcp.ports, vec![22, 3389]);
        // 缺失的阈值走 ProtectionRule::default
        assert_eq!(c.protect.tcp.max_attempts, 5);
    }

    #[test]
    fn 旧配置里的窗口字段被忽略而不报错() {
        // 窗口判定已废弃，旧版本写下的 window_seconds 必须能照常读入。
        let c = Config::from_toml("[protect.tcp]\nports = [3389]\nwindow_seconds = 10\nmax_attempts = 3\n")
            .unwrap();
        assert_eq!(c.protect.tcp.ports, vec![3389]);
        assert_eq!(c.protect.tcp.max_attempts, 3);
    }

    #[test]
    fn 端口规范化去重排序() {
        let mut r = ProtectionRule {
            ports: vec![443, 80, 443, 0, 3389],
            max_attempts: 0,
        };
        r.normalize();
        assert_eq!(r.ports, vec![80, 443, 3389]);
        assert_eq!(r.max_attempts, 1);
    }

    #[test]
    fn 非法白名单能被校验发现() {
        let mut c = Config::with_defaults();
        c.lists.whitelist = vec!["这不是IP".to_string()];
        let errs = c.validate();
        assert!(!errs.is_empty());
        assert!(errs[0].contains("白名单"));
    }

    #[test]
    fn 非法面板地址能被校验发现() {
        let mut c = Config::with_defaults();
        c.panel.bind = "127.0.0.1".to_string();
        assert!(!c.validate().is_empty());
    }

    #[test]
    fn 地理配置默认开启且文件名可回退() {
        let mut c = Config::with_defaults();
        assert!(c.geo.enabled, "默认应展示地理位置");
        assert_eq!(c.geo.db, DEFAULT_GEO_DB);
        // 用户把文件名清空时回退默认值，而不是留下一个找不到的路径
        c.geo.db = "   ".to_string();
        c.normalize();
        assert_eq!(c.geo.db, DEFAULT_GEO_DB);
    }

    #[test]
    fn 保护端口全空会被校验拒绝() {
        let mut c = Config::with_defaults();
        c.protect.tcp.ports.clear();
        c.protect.http.ports.clear();
        c.protect.udp.ports.clear();
        assert!(!c.has_any_protected_port());
        let errs = c.validate();
        assert!(
            errs.iter().any(|e| e.contains("保护端口为空")),
            "三组全空必须拒绝保存，实际错误={:?}",
            errs
        );
    }

    #[test]
    fn 只要有一组保护端口就放行() {
        let mut c = Config::with_defaults();
        c.protect.http.ports.clear();
        c.protect.udp.ports.clear();
        // 只留 TCP 3389
        assert!(c.has_any_protected_port());
        assert!(c.validate().is_empty());
    }

    #[test]
    fn 注释与空行在规范化时被剔除() {
        let mut c = Config::with_defaults();
        c.lists.blacklist = vec![
            "".to_string(),
            "  ".to_string(),
            "# 注释".to_string(),
            " 1.2.3.4 ".to_string(),
        ];
        c.normalize();
        assert_eq!(c.lists.blacklist, vec!["1.2.3.4"]);
    }
}
