//! HTTP 路由与 JSON 接口。
//!
//! 设计原则：
//! - 路由层是**纯函数**：输入「方法 + 路径 + 查询串 + 请求体」，
//!   输出一个 `Reply`，不接触 socket，因此可以用 Mock API 完整单元测试；
//! - 所有变更接口只接受 JSON 请求体，不接受查询串传参，避免日志与
//!   浏览器历史里留下会被误触发的 URL；
//! - 错误一律以 `{"error":"中文说明"}` 返回，前端直接展示这句话。

use portguard_core::api::{PortGuardApi, ProtectionSwitch};
use portguard_core::config::Config;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::assets;

/// 路由处理结果。
#[derive(Debug)]
pub enum Reply {
    /// JSON 响应。
    Json(String),
    /// 内嵌静态资源。
    Asset {
        mime: &'static str,
        body: &'static str,
    },
    /// 无内容（204）。
    NoContent,
    /// 错误响应。
    Error { status: u16, message: String },
}

impl Reply {
    pub fn json(v: Value) -> Reply {
        Reply::Json(v.to_string())
    }

    /// 由序列化结果构造；序列化失败说明内部数据结构有问题，如实报 500。
    pub fn from_serializable<T: serde::Serialize>(v: &T) -> Reply {
        match serde_json::to_string(v) {
            Ok(s) => Reply::Json(s),
            Err(e) => Reply::Error {
                status: 500,
                message: format!("序列化响应失败：{}", e),
            },
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Reply {
        Reply::Error {
            status: 400,
            message: message.into(),
        }
    }

    /// HTTP 状态码。
    pub fn status(&self) -> u16 {
        match self {
            Reply::Json(_) | Reply::Asset { .. } => 200,
            Reply::NoContent => 204,
            Reply::Error { status, .. } => *status,
        }
    }

    /// 响应体（供测试断言）。
    pub fn body(&self) -> &str {
        match self {
            Reply::Json(s) => s,
            Reply::Asset { body, .. } => body,
            Reply::NoContent => "",
            Reply::Error { message, .. } => message,
        }
    }
}

/// 面板元信息（与业务无关的运行期常量）。
#[derive(Clone, Debug)]
pub struct PanelMeta {
    pub version: String,
    pub log_file: String,
    pub data_dir: String,
    pub started_at_ms: u64,
    /// 服务器系统语言（`"zh"` / `"en"`，启动时探测一次）。
    ///
    /// 面板语言设置为 `auto` 时用它决定界面语言；`/api/meta` 每次请求都按
    /// **当前配置**重新解析，因此改完设置立即生效，不必重启程序。
    pub system_language: String,
}

/// 变更类请求体。
#[derive(Debug, Deserialize)]
struct BanBody {
    ip: String,
    #[serde(default)]
    permanent: bool,
}

#[derive(Deserialize)]
struct IpBody {
    ip: String,
}

#[derive(Deserialize)]
struct ListBody {
    kind: String,
    rule: String,
}

#[derive(Deserialize)]
struct AdapterBody {
    ip: String,
}

#[derive(Deserialize)]
struct ProtectionBody {
    key: String,
    enabled: bool,
}

/// 把核心层的错误转成 400/500 响应。
///
/// 参数错误（非法 IP、非法规则、白名单冲突等）属于客户端问题，返回 400；
/// 其余（防火墙失败、权限不足等）属于服务端问题，返回 500。
fn map_error(e: portguard_core::error::AppError) -> Reply {
    use portguard_core::error::AppError as E;
    let status = match &e {
        E::InvalidIpRule(_) | E::Config(_) => 400,
        _ => 500,
    };
    Reply::Error {
        status,
        message: e.to_string(),
    }
}

/// 解析监听地址字符串中的主机部分，供 Host 头校验使用。
///
/// 因为面板只监听回环，合法来源只可能是 `127.0.0.1` / `localhost` / `[::1]`。
pub fn allowed_hosts(bind: &str) -> Vec<String> {
    let port = bind.rsplit(':').next().unwrap_or("");
    let mut hosts = vec![
        // 用户可能把面板绑到指定网卡后按该地址访问，本身必须放行
        bind.to_string(),
        format!("127.0.0.1:{}", port),
        format!("localhost:{}", port),
        format!("[::1]:{}", port),
    ];
    hosts.dedup();
    hosts
}

/// 判断 Host 头是否属于本机回环。
///
/// 这道校验用于阻断 DNS rebinding：攻击者可以让自己的域名解析到 127.0.0.1，
/// 诱导浏览器带着该域名访问本地面板并执行变更操作。要求 Host 必须是本机字样，
/// 这类请求会被直接拒绝。
pub fn host_allowed(host: &str, bind: &str) -> bool {
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    allowed_hosts(bind)
        .iter()
        .any(|h| h.to_ascii_lowercase() == host)
}

/// 路由入口。
///
/// `method` 为大写方法名，`path` 为不含查询串的路径，`query` 为 `?` 之后的部分。
pub fn handle(
    api: &dyn PortGuardApi,
    meta: &PanelMeta,
    method: &str,
    path: &str,
    query: &str,
    body: &str,
) -> Reply {
    match (method, path) {
        // ---- 静态资源 ----
        ("GET" | "HEAD", "/") | ("GET" | "HEAD", "/index.html") => Reply::Asset {
            mime: "text/html; charset=utf-8",
            body: assets::INDEX_HTML,
        },
        ("GET" | "HEAD", "/favicon.ico") => Reply::NoContent,
        ("GET" | "HEAD", p) if p.starts_with("/assets/") => match assets::lookup(p) {
            Some(a) => Reply::Asset {
                mime: a.mime,
                body: a.body,
            },
            None => Reply::Error {
                status: 404,
                message: "资源不存在".to_string(),
            },
        },

        // ---- 只读接口 ----
        ("GET", "/api/state") => handle_state(api),
        ("GET", "/api/status") => Reply::from_serializable(&api.status()),
        ("GET", "/api/connections") => Reply::from_serializable(&api.connections()),
        ("GET", "/api/bans") => Reply::from_serializable(&api.bans()),
        ("GET", "/api/config") => Reply::from_serializable(&api.config()),
        ("GET", "/api/adapters") => Reply::from_serializable(&api.adapters()),
        ("GET", "/api/logs") => {
            Reply::from_serializable(&api.logs(parse_limit(query, 300, 5000)))
        }
        ("GET", "/api/events") => {
            Reply::from_serializable(&api.events(parse_limit(query, 100, 1000)))
        }
        ("GET", "/api/meta") => Reply::json(json!({
            "version": meta.version,
            "log_file": meta.log_file,
            "data_dir": meta.data_dir,
            "started_at_ms": meta.started_at_ms,
            // 界面语言：按当前配置解析（auto 时用服务器系统语言），
            // 前端拿到后立即切换文案，因此保存设置即生效
            "language": api.config().panel.effective_language(&meta.system_language),
        })),

        // ---- 变更接口 ----
        ("POST", "/api/start") => match api.start() {
            Ok(()) => ok(),
            Err(e) => map_error(e),
        },
        ("POST", "/api/stop") => match api.stop() {
            Ok(()) => ok(),
            Err(e) => map_error(e),
        },
        ("POST", "/api/ban") => match parse::<BanBody>(body) {
            Ok(b) => match parse_ip(&b.ip) {
                Ok(ip) => match api.ban_ip(ip, b.permanent) {
                    Ok(()) => ok(),
                    Err(e) => map_error(e),
                },
                Err(r) => r,
            },
            Err(r) => r,
        },
        ("POST", "/api/unban") => match parse::<IpBody>(body) {
            Ok(b) => match parse_ip(&b.ip) {
                Ok(ip) => match api.unban_ip(ip) {
                    Ok(()) => ok(),
                    Err(e) => map_error(e),
                },
                Err(r) => r,
            },
            Err(r) => r,
        },
        ("POST", "/api/lists/add") => match parse::<ListBody>(body) {
            Ok(b) => match b.kind.as_str() {
                "whitelist" => match api.whitelist_add(&b.rule) {
                    Ok(()) => ok(),
                    Err(e) => map_error(e),
                },
                "blacklist" => match api.blacklist_add(&b.rule) {
                    Ok(()) => ok(),
                    Err(e) => map_error(e),
                },
                other => Reply::bad_request(format!("未知名单类型：{}", other)),
            },
            Err(r) => r,
        },
        ("POST", "/api/lists/remove") => match parse::<ListBody>(body) {
            Ok(b) => match b.kind.as_str() {
                "whitelist" => match api.whitelist_remove(&b.rule) {
                    Ok(()) => ok(),
                    Err(e) => map_error(e),
                },
                "blacklist" => match api.blacklist_remove(&b.rule) {
                    Ok(()) => ok(),
                    Err(e) => map_error(e),
                },
                other => Reply::bad_request(format!("未知名单类型：{}", other)),
            },
            Err(r) => r,
        },
        ("POST", "/api/adapter") => match parse::<AdapterBody>(body) {
            Ok(b) => match api.select_adapter(&b.ip) {
                Ok(()) => ok(),
                Err(e) => map_error(e),
            },
            Err(r) => r,
        },
        ("POST", "/api/protection") => match parse::<ProtectionBody>(body) {
            Ok(b) => match protection_key(&b.key) {
                Some(k) => match api.set_protection(k, b.enabled) {
                    Ok(()) => ok(),
                    Err(e) => map_error(e),
                },
                None => Reply::bad_request(format!("未知的保护开关：{}", b.key)),
            },
            Err(r) => r,
        },
        ("POST", "/api/config") => match parse::<Config>(body) {
            Ok(cfg) => match api.save_config(cfg) {
                Ok(saved) => Reply::from_serializable(&saved),
                Err(e) => map_error(e),
            },
            Err(r) => r,
        },

        _ => Reply::Error {
            status: 404,
            message: format!("未知接口：{} {}", method, path),
        },
    }
}

fn ok() -> Reply {
    Reply::json(json!({ "ok": true }))
}

fn handle_state(api: &dyn PortGuardApi) -> Reply {
    Reply::json(json!({
        "status": api.status(),
        "connections": api.connections(),
        "bans": api.bans(),
        "events": api.events(80),
    }))
}

fn parse<T: for<'de> Deserialize<'de>>(body: &str) -> Result<T, Reply> {
    if body.trim().is_empty() {
        return Err(Reply::bad_request("请求体为空，需提供 JSON"));
    }
    serde_json::from_str::<T>(body).map_err(|e| Reply::bad_request(format!("请求体格式错误：{}", e)))
}

fn parse_ip(s: &str) -> Result<portguard_core::model::Ip, Reply> {
    s.trim()
        .parse()
        .map_err(|_| Reply::bad_request(format!("IP 地址非法：{}", s)))
}

fn protection_key(key: &str) -> Option<ProtectionSwitch> {
    match key {
        "risky_ports" => Some(ProtectionSwitch::RiskyPorts),
        "block_icmp" => Some(ProtectionSwitch::BlockIcmp),
        "autostart" => Some(ProtectionSwitch::Autostart),
        "rdp_guard" => Some(ProtectionSwitch::RdpGuard),
        _ => None,
    }
}

/// 解析 `?limit=200` 形式的整数参数，并在给定区间内夹取。
fn parse_limit(query: &str, default: usize, max: usize) -> usize {
    for pair in query.split('&') {
        if let Some(v) = pair.strip_prefix("limit=") {
            if let Ok(n) = v.parse::<usize>() {
                return n.clamp(1, max);
            }
        }
    }
    default
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 限制参数被正确夹取() {
        assert_eq!(parse_limit("", 300, 5000), 300);
        assert_eq!(parse_limit("limit=50", 300, 5000), 50);
        assert_eq!(parse_limit("limit=999999", 300, 5000), 5000);
        assert_eq!(parse_limit("limit=0", 300, 5000), 1);
        assert_eq!(parse_limit("limit=abc", 300, 5000), 300);
        assert_eq!(parse_limit("foo=1&limit=7", 300, 5000), 7);
    }

    #[test]
    fn 主机校验只接受回环() {
        let bind = "127.0.0.1:58080";
        assert!(host_allowed("127.0.0.1:58080", bind));
        assert!(host_allowed("LOCALHOST:58080", bind));
        assert!(host_allowed("localhost:58080", bind));
        assert!(host_allowed("[::1]:58080", bind));
        // DNS rebinding 场景：攻击者域名解析到 127.0.0.1，Host 头仍是攻击者域名
        assert!(!host_allowed("evil.example.com:58080", bind));
        assert!(!host_allowed("127.0.0.1:9999", bind), "端口不符必须拒绝");
        assert!(!host_allowed("", bind));
    }

    #[test]
    fn 保护开关名称映射() {
        assert_eq!(protection_key("risky_ports"), Some(ProtectionSwitch::RiskyPorts));
        assert_eq!(protection_key("block_icmp"), Some(ProtectionSwitch::BlockIcmp));
        assert_eq!(protection_key("autostart"), Some(ProtectionSwitch::Autostart));
        assert_eq!(protection_key("rdp_guard"), Some(ProtectionSwitch::RdpGuard));
        assert_eq!(protection_key("随便写的"), None);
    }

    #[test]
    fn 非法请求体返回四百() {
        let r = parse::<BanBody>("");
        assert_eq!(r.unwrap_err().status(), 400);
        let r = parse::<BanBody>("{不是 JSON}");
        assert_eq!(r.unwrap_err().status(), 400);
    }

    #[test]
    fn 非法ip被拒绝() {
        let r = parse_ip("999.1.1.1");
        assert_eq!(r.unwrap_err().status(), 400);
        assert!(parse_ip(" 1.2.3.4 ").is_ok(), "两侧空白应被容忍");
    }

    #[test]
    fn 响应状态码符合语义() {
        assert_eq!(Reply::json(json!({})).status(), 200);
        assert_eq!(Reply::bad_request("x").status(), 400);
        assert_eq!(Reply::NoContent.status(), 204);
    }
}
