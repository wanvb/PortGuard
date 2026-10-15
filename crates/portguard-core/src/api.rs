//! 面向表现层的只读视图与 API 契约。
//!
//! Web 层只依赖本模块定义的 trait 与视图结构，不认识 `BanManager` / `RuleEngine`
//! 的内部结构（对应规范 18 的 UI / Core 解耦，只是把「Win32 UI」换成了「Web UI」）。

use crate::config::Config;
use crate::error::Result;
use crate::logging::LogLine;
use crate::model::{BanReason, Ip, Protocol, Statistics};
use serde::{Deserialize, Serialize};

/// 面板顶部状态条数据。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusView {
    /// 是否正在监听。
    pub running: bool,
    /// 当前选定网卡的展示名（空表示未选择）。
    pub adapter: String,
    /// 监听的本机 IP。
    pub local_ip: String,
    /// 面板监听地址。
    pub panel_bind: String,
    /// 是否具备管理员权限。
    pub admin: bool,
    /// 抓包后端是否已就绪。
    pub capture_ready: bool,
    /// 聚合统计。
    pub stats: Statistics,
    /// 进程启动时间（Unix 纪元毫秒）。
    pub started_at_ms: u64,
    /// 版本号。
    pub version: String,
    /// 受保护端口总数。
    pub protected_ports: usize,
    /// 当前生效的系统保护开关。
    pub risky_ports: bool,
    pub block_icmp: bool,
    pub autostart: bool,
    pub rdp_enabled: bool,
    /// 地理位置库是否已加载（未加载时列表中的地理位置恒为「未知」）。
    pub geo_ready: bool,
    /// 地理位置库状态说明：加载成功时是数据库路径，否则是中文原因。
    pub geo_status: String,
    /// 抓包层解析失败的包数（非 IPv4 / 分片 / 畸形包）。
    ///
    /// 与 `captured_packets` 一起看：若目标端口的包既没进连接列表、
    /// 也没出现在观测表里，而这里在涨，说明是解析层丢的，不是没抓到。
    pub parse_errors: u64,
    /// 最近几次解析失败的样本说明（最多 3 条）。
    pub parse_samples: Vec<String>,
    /// 抓包观测：实际收到的包按「方向 + 协议 + 端口 + 标志」分类的 Top N。
    pub observed: Vec<ObservedPortView>,
    /// 当前是否把服务端握手响应（SYN+ACK）当作连接事件。
    pub count_accept: bool,
}

/// 抓包观测行（纯诊断展示）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObservedPortView {
    /// 方向：`入站` / `出站`。
    pub direction: String,
    /// 协议：`TCP` / `UDP` / `ICMP`。
    pub protocol: String,
    /// 本机侧端口（非本机流量为 0）。
    pub port: u16,
    /// TCP 标志类别：`SYN` / `SYN+ACK` / `ACK` / `FIN` / `RST` / `其它`。
    pub flags: String,
    /// 观察到的包数。
    pub count: u64,
}

/// 「当前连接 / 跟踪中」列表行。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionView {
    pub ip: String,
    /// 保护分组：`TCP` / `TCP-WEB` / `UDP`。
    pub group: String,
    pub service_port: u16,
    /// 累计连接次数（达到 `threshold` 即封停）。
    pub count: u32,
    /// 首次出现时间（Unix 纪元毫秒）。
    pub first_seen_ms: u64,
    /// 最近出现时间（Unix 纪元毫秒）。
    pub last_seen_ms: u64,
    /// 当前阈值。
    pub threshold: u32,
    /// 当前状态：`TRACKING` / `BANNED` / `PERMANENT` / `WHITELIST`。
    pub state: String,
    /// 是否命中白名单。
    pub whitelisted: bool,
    /// 来源 IP 的地理位置，仅供展示（查不到为「未知」，规范 22）。
    pub location: String,
    /// 该行服务端口的备注，仅供展示（无备注为空串）。
    pub port_note: String,
    /// 来源 IP 在名单里的备注，仅供展示（无备注为空串）。
    pub ip_note: String,
}

/// 「封停列表」行。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BanView {
    pub ip: String,
    pub reason: String,
    pub reason_label: String,
    pub protocol: String,
    pub service_port: Option<u16>,
    pub remote_port: Option<u16>,
    pub attempt_count: u32,
    pub created_at_ms: u64,
    pub expires_at_ms: Option<u64>,
    pub permanent: bool,
    /// 剩余秒数；永久封停为 `None`。
    pub remaining_seconds: Option<u64>,
    /// 防火墙规则名，便于运维核对。
    pub rule_name: String,
    /// 被封停 IP 的地理位置，仅供展示（查不到为「未知」，规范 22）。
    pub location: String,
    /// 封停端口的备注，仅供展示（无备注为空串）。
    pub port_note: String,
    /// 被封停 IP 在名单里的备注，仅供展示（无备注为空串）。
    pub ip_note: String,
}

/// 网卡列表项。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdapterView {
    /// 网卡 IPv4 地址。
    pub ip: String,
    /// 子网掩码。
    pub mask: String,
    /// 网卡描述（驱动友好名）。
    pub description: String,
    /// 是否为虚拟网卡（VMware / Hyper-V / 虚拟回环等）。
    pub is_virtual: bool,
    /// 是否已选中。
    pub selected: bool,
    /// 是否可用（排除 0.0.0.0 与回环）。
    pub usable: bool,
}

/// 关键事件行（比日志更结构化，供面板「事件流」展示）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventView {
    pub ts_ms: u64,
    /// 事件类型标识，前端据此着色。
    pub kind: String,
    /// 中文描述。
    pub message: String,
    /// 关联 IP（可为空）。
    pub ip: Option<String>,
}

/// 封停请求的判定来源，供日志区分「界面手动」与「程序内部」。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BanSource {
    /// 用户在 Web 面板点击封停。
    Manual,
    /// 程序内部（阈值 / 黑名单）。
    Automatic,
}

/// 表现层调用核心的唯一入口。
///
/// 所有方法都必须是「快速返回」的：实现方内部通过 channel / 锁交给工作线程，
/// 绝不在本 trait 的实现里做阻塞 I/O（规范 44）。
pub trait PortGuardApi: Send + Sync {
    /// 取状态条数据。
    fn status(&self) -> StatusView;

    /// 取跟踪中的连接行。
    fn connections(&self) -> Vec<ConnectionView>;

    /// 取封停列表。
    fn bans(&self) -> Vec<BanView>;

    /// 取当前配置快照。
    fn config(&self) -> Config;

    /// 校验并保存配置，保存后热更新运行期参数。
    fn save_config(&self, cfg: Config) -> Result<Config>;

    /// 开始监听。
    fn start(&self) -> Result<()>;

    /// 停止监听（保留封停记录）。
    fn stop(&self) -> Result<()>;

    /// 封停指定 IP。
    fn ban_ip(&self, ip: Ip, permanent: bool) -> Result<()>;

    /// 解封指定 IP。
    fn unban_ip(&self, ip: Ip) -> Result<()>;

    /// 加入白名单（并自动解封）。
    fn whitelist_add(&self, rule: &str) -> Result<()>;

    /// 加入黑名单（并立即封停）。
    fn blacklist_add(&self, rule: &str) -> Result<()>;

    /// 删除白名单规则。
    fn whitelist_remove(&self, rule: &str) -> Result<()>;

    /// 删除黑名单规则。
    fn blacklist_remove(&self, rule: &str) -> Result<()>;

    /// 取最近日志。
    fn logs(&self, limit: usize) -> Vec<LogLine>;

    /// 取最近事件。
    fn events(&self, limit: usize) -> Vec<EventView>;

    /// 枚举本机网卡。
    fn adapters(&self) -> Vec<AdapterView>;

    /// 切换监听网卡。
    fn select_adapter(&self, ip: &str) -> Result<()>;

    /// 开关系统保护项。
    fn set_protection(&self, key: ProtectionSwitch, enabled: bool) -> Result<()>;

    /// 立即打开日志目录（返回路径供前端提示）。
    fn data_dir(&self) -> String;
}

/// 系统保护开关标识。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionSwitch {
    /// 危险端口保护（135/137/138/139/445）。
    RiskyPorts,
    /// 禁止 Ping。
    BlockIcmp,
    /// 开机自动启动。
    Autostart,
    /// RDP 客户端计算机名保护。
    RdpGuard,
}

/// 把 `Protocol` 转成面板展示用的字符串。
pub fn protocol_label(p: Option<Protocol>) -> String {
    match p {
        Some(x) => x.as_str().to_string(),
        None => "-".to_string(),
    }
}

/// 把 `BanReason` 转成展示文案。
pub fn reason_label(r: BanReason) -> String {
    r.label().to_string()
}
