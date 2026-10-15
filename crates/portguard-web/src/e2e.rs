//! 端到端验证：真实监听回环端口，用裸 TCP 发请求，检查完整链路。
//!
//! 不用 HTTP 客户端库：手写请求可以精确控制 Host / Origin 头，
//! 而这正是本层安全校验的输入。

#![cfg(test)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use portguard_core::logging::Level;
use portguard_storage::Logger;

use crate::router::PanelMeta;
use crate::server::WebServer;
use crate::testapi::MockApi;

/// 每个测试独占一个工作目录。
fn unique_dir() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("pg_web_{}_{}", std::process::id(), n));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// 一次测试用的服务实例。服务放在 `Option` 里，方便个别测试提前取走并停止。
struct Harness {
    server: Option<WebServer>,
    last_addr: String,
    /// 持有日志器直到测试结束，避免工作线程提前退出。
    _logger: Arc<Logger>,
    dir: std::path::PathBuf,
}

impl Harness {
    fn start() -> Harness {
        let dir = unique_dir();
        let logger = Arc::new(
            Logger::start(&dir.join("test.log"), Level::Debug, 100).expect("创建测试日志器失败"),
        );
        let api = Arc::new(MockApi::new());
        let meta = PanelMeta {
            version: "test".to_string(),
            log_file: dir.join("test.log").display().to_string(),
            data_dir: dir.display().to_string(),
            started_at_ms: 1_700_000_000_000,
            // 固定成英文系统：配置里的 auto 才有可断言的确定结果
            system_language: "en".to_string(),
        };
        // 端口 0 → 由系统分配，避免与正在运行的 PortGuard 抢 58080
        let server =
            WebServer::start(api, meta, "127.0.0.1:0", Arc::clone(&logger)).expect("启动面板失败");
        let last_addr = server.addr().to_string();
        Harness {
            server: Some(server),
            last_addr,
            _logger: logger,
            dir,
        }
    }

    fn addr(&self) -> String {
        self.last_addr.clone()
    }

    /// 取走服务对象（用于停止测试，之后 `addr()` 仍返回原地址）。
    fn take_server(&mut self) -> WebServer {
        match self.server.take() {
            Some(s) => s,
            // 只会在重复调用时发生，测试自身已保证不会
            None => panic!("服务已被取走"),
        }
    }

    /// 发送原始请求并取回完整响应文本。
    fn raw(&self, request: &str) -> String {
        let mut stream = TcpStream::connect(self.addr()).expect("连接面板失败");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("设置超时失败");
        stream
            .write_all(request.as_bytes())
            .expect("写入请求失败");
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).to_string()
    }

    /// 发一个带正确 Host 的 GET。
    fn get(&self, path: &str) -> String {
        self.raw(&format!(
            "GET {} HTTP/1.0\r\nHost: {}\r\n\r\n",
            path,
            self.addr()
        ))
    }

    /// 发一个带正确 Host 的 POST。
    fn post(&self, path: &str, body: &str) -> String {
        self.raw(&format!(
            "POST {} HTTP/1.0\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            path,
            self.addr(),
            body.len(),
            body
        ))
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// 从响应文本中截取「状态行与响应头」和「响应体」。
///
/// 返回拥有所有权的字符串，这样调用方可以直接写
/// `split_response(&h.get(path))`，不必为每个临时值单独绑一个变量。
fn split_response(text: &str) -> (String, String) {
    match text.find("\r\n\r\n") {
        Some(i) => (text[..i].to_string(), text[i + 4..].to_string()),
        None => (text.to_string(), String::new()),
    }
}

#[test]
fn 首页与静态资源可访问() {
    let h = Harness::start();

    let (head, body) = split_response(&h.get("/"));
    assert!(head.starts_with("HTTP/1.0 200") || head.starts_with("HTTP/1.1 200"));
    assert!(head.contains("text/html"));
    assert!(body.contains("PortGuard"), "首页应包含品牌名");
    // 判定明细区与受保护端口明细是排查「端口无记录」的入口，不能被删掉
    assert!(body.contains("ignore-stats"), "首页应包含判定明细容器");
    assert!(body.contains("stat-ports-foot"), "受保护端口卡应有明细脚注");
    assert!(body.contains("tbody-observe"), "首页应包含抓包观测表格");
    assert!(body.contains("cfg-count-accept"), "设置页应包含连接事件来源开关");

    let (head, body) = split_response(&h.get("/assets/app.js"));
    assert!(head.contains("200"));
    assert!(head.contains("javascript"));
    assert!(body.contains("refreshState"), "脚本内容应完整返回");

    let (head, _) = split_response(&h.get("/assets/style.css"));
    assert!(head.contains("200"));
    assert!(head.contains("text/css"));

    let (head, _) = split_response(&h.get("/assets/nope.js"));
    assert!(head.contains("404"));
}

#[test]
fn 状态接口返回完整聚合数据() {
    let h = Harness::start();
    let (head, body) = split_response(&h.get("/api/state"));
    assert!(head.contains("200"));
    assert!(head.contains("application/json"));

    let v: serde_json::Value = serde_json::from_str(&body).expect("响应不是合法 JSON");
    assert_eq!(v["status"]["running"], true);
    assert_eq!(v["status"]["version"], "test");
    assert_eq!(v["connections"].as_array().map(|a| a.len()), Some(1));
    assert_eq!(v["bans"].as_array().map(|a| a.len()), Some(1));
    assert!(v["events"].as_array().is_some());
    // 白名单与端口统计必须一起下发，否则概览页会显示错误数字
    assert_eq!(v["status"]["protected_ports"], 4);
    // 判定明细的五个计数必须与状态一起下发（面板首屏即依赖）
    for key in [
        "not_local",
        "outbound",
        "not_new_connection",
        "port_not_protected",
        "icmp",
    ] {
        assert!(
            v["status"]["stats"]["ignored"][key].is_number(),
            "判定明细缺少字段 {}",
            key
        );
    }
}

#[test]
fn 保护端口全空必须被拒绝() {
    let h = Harness::start();
    let body = split_response(&h.get("/api/config")).1;
    let mut cfg: serde_json::Value = serde_json::from_str(&body).unwrap();
    cfg["protect"]["tcp"]["ports"] = serde_json::json!([]);
    cfg["protect"]["http"]["ports"] = serde_json::json!([]);
    cfg["protect"]["udp"]["ports"] = serde_json::json!([]);

    let (head, out) = split_response(&h.post("/api/config", &cfg.to_string()));
    assert!(head.contains("400"), "三组全空必须拒绝：{} {}", head, out);
    assert!(out.contains("保护端口为空"), "错误提示应指明原因：{}", out);

    // 原配置保持不变
    let back: serde_json::Value = serde_json::from_str(&split_response(&h.get("/api/config")).1).unwrap();
    assert_eq!(back["protect"]["tcp"]["ports"][0], 3389);
}

#[test]
fn 只读接口逐一可用() {
    let h = Harness::start();
    for path in [
        "/api/status",
        "/api/connections",
        "/api/bans",
        "/api/config",
        "/api/adapters",
        "/api/logs?limit=10",
        "/api/events?limit=10",
        "/api/meta",
    ] {
        let (head, body) = split_response(&h.get(path));
        assert!(head.contains("200"), "{} 未返回 200：{}", path, head);
        assert!(
            serde_json::from_str::<serde_json::Value>(&body).is_ok(),
            "{} 返回的不是 JSON：{}",
            path,
            body
        );
    }
}

#[test]
fn 界面语言随设置切换且无需重启() {
    let h = Harness::start();
    let language = |h: &Harness| -> String {
        let body = split_response(&h.get("/api/meta")).1;
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["language"]
            .as_str()
            .unwrap_or("")
            .to_string()
    };

    // 默认 auto：跟随服务器系统语言（本测试固定为英文）
    assert_eq!(language(&h), "en");

    // 改成中文：写盘成功的同一份配置必须让界面语言立即变过来，不必重启程序
    let body = split_response(&h.get("/api/config")).1;
    let mut cfg: serde_json::Value = serde_json::from_str(&body).unwrap();
    cfg["panel"]["language"] = serde_json::json!("zh");
    let (head, _) = split_response(&h.post("/api/config", &cfg.to_string()));
    assert!(head.contains("200"), "保存语言设置失败：{}", head);
    assert_eq!(language(&h), "zh");

    // 改回 auto：重新跟随系统
    cfg["panel"]["language"] = serde_json::json!("auto");
    let (head, _) = split_response(&h.post("/api/config", &cfg.to_string()));
    assert!(head.contains("200"), "保存语言设置失败：{}", head);
    assert_eq!(language(&h), "en");

    // 胡乱写一个值：规范化回 auto，而不是留一个永不生效的设置
    cfg["panel"]["language"] = serde_json::json!("klingon");
    let (head, saved) = split_response(&h.post("/api/config", &cfg.to_string()));
    assert!(head.contains("200"), "保存语言设置失败：{}", head);
    let saved: serde_json::Value = serde_json::from_str(&saved).unwrap();
    assert_eq!(saved["panel"]["language"], "auto");
    assert_eq!(language(&h), "en");
}

#[test]
fn 封停与解封链路生效() {
    let h = Harness::start();

    let (head, body) = split_response(&h.post("/api/ban", r#"{"ip":"198.51.100.7","permanent":true}"#));
    assert!(head.contains("200"), "封停请求失败：{} {}", head, body);

    // 封停后应出现在封停列表、从连接列表消失
    let body = split_response(&h.get("/api/state")).1;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let ips: Vec<&str> = v["bans"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["ip"].as_str().unwrap())
        .collect();
    assert!(ips.contains(&"198.51.100.7"));
    assert!(v["connections"].as_array().unwrap().is_empty());

    let (head, _) = split_response(&h.post("/api/unban", r#"{"ip":"198.51.100.7"}"#));
    assert!(head.contains("200"));
    let body = split_response(&h.get("/api/bans")).1;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 1, "应只剩测试初始的那条记录");
}

#[test]
fn 白名单地址封停被拒绝并返回中文原因() {
    let h = Harness::start();
    let (head, body) = split_response(&h.post("/api/ban", r#"{"ip":"10.0.0.1","permanent":true}"#));
    assert!(head.contains("500"), "白名单冲突应报错：{}", head);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        v["error"].as_str().unwrap().contains("白名单"),
        "错误信息必须说明原因：{}",
        body
    );
}

#[test]
fn 非法参数返回四百而非五百() {
    let h = Harness::start();

    let (head, _) = split_response(&h.post("/api/ban", r#"{"ip":"999.1.1.1"}"#));
    assert!(head.contains("400"), "非法 IP 属于客户端错误：{}", head);

    let (head, _) = split_response(&h.post("/api/ban", "{不是JSON}"));
    assert!(head.contains("400"));

    let (head, _) = split_response(&h.post("/api/protection", r#"{"key":"不存在的开关","enabled":true}"#));
    assert!(head.contains("400"));

    let (head, _) = split_response(&h.post("/api/lists/add", r#"{"kind":"graylist","rule":"1.2.3.4"}"#));
    assert!(head.contains("400"));

    let (head, _) = split_response(&h.get("/api/nonexistent"));
    assert!(head.contains("404"), "未知接口应返回 404：{}", head);
    let (head, _) = split_response(&h.get("/totally/unknown"));
    assert!(head.contains("404"));
}

#[test]
fn 保存配置生效() {
    let h = Harness::start();

    let body = split_response(&h.get("/api/config")).1;
    let mut cfg: serde_json::Value = serde_json::from_str(&body).unwrap();
    cfg["ban"]["duration_seconds"] = serde_json::json!(7200);
    cfg["lists"]["blacklist"] = serde_json::json!(["1.2.3.0/24"]);
    cfg["system"]["block_icmp"] = serde_json::json!(true);

    let (head, out) = split_response(&h.post("/api/config", &cfg.to_string()));
    assert!(head.contains("200"), "保存配置失败：{} {}", head, out);

    let back: serde_json::Value = serde_json::from_str(&split_response(&h.get("/api/config")).1).unwrap();
    assert_eq!(back["ban"]["duration_seconds"], 7200);
    assert_eq!(back["lists"]["blacklist"][0], "1.2.3.0/24");
    assert_eq!(back["system"]["block_icmp"], true);
}

#[test]
fn 端口与名单备注随配置往返并可展示() {
    let h = Harness::start();

    let body = split_response(&h.get("/api/config")).1;
    let mut cfg: serde_json::Value = serde_json::from_str(&body).unwrap();
    // 端口备注的键是十进制字符串，名单备注的键是规则原文
    cfg["protect"]["tcp"]["ports"] = serde_json::json!([3389, 33890]);
    cfg["protect"]["tcp"]["notes"] = serde_json::json!({ "33890": "frp: 财务系统" });
    cfg["lists"]["notes"] = serde_json::json!({ "10.0.0.1": "办公机 · 张三" });

    let (head, out) = split_response(&h.post("/api/config", &cfg.to_string()));
    assert!(head.contains("200"), "保存带备注的配置失败：{} {}", head, out);

    let back: serde_json::Value =
        serde_json::from_str(&split_response(&h.get("/api/config")).1).unwrap();
    assert_eq!(back["protect"]["tcp"]["notes"]["33890"], "frp: 财务系统");
    assert_eq!(back["lists"]["notes"]["10.0.0.1"], "办公机 · 张三");

    // 数据表页的备注由后端随视图下发，前端只负责内联显示
    let state: serde_json::Value =
        serde_json::from_str(&split_response(&h.get("/api/state")).1).unwrap();
    assert_eq!(state["connections"][0]["port_note"], "远程桌面");
    assert_eq!(state["connections"][0]["ip_note"], "办公机 · 张三");
    assert_eq!(state["bans"][0]["port_note"], "远程桌面");
}

#[test]
fn 非法配置被拒绝且不落盘() {
    let h = Harness::start();
    let body = split_response(&h.get("/api/config")).1;
    let mut cfg: serde_json::Value = serde_json::from_str(&body).unwrap();
    cfg["lists"]["whitelist"] = serde_json::json!(["这不是IP"]);

    let (head, out) = split_response(&h.post("/api/config", &cfg.to_string()));
    assert!(head.contains("400"), "非法配置必须被拒绝：{}", head);
    assert!(out.contains("白名单"));

    // 原配置保持不变
    let back: serde_json::Value = serde_json::from_str(&split_response(&h.get("/api/config")).1).unwrap();
    assert_eq!(back["lists"]["whitelist"][0], "10.0.0.1");
}

#[test]
fn 陌生主机头被拒绝() {
    let h = Harness::start();
    // DNS rebinding 场景：域名解析到 127.0.0.1，但 Host 头是攻击者域名
    let text = h.raw("GET /api/state HTTP/1.0\r\nHost: evil.example.com\r\n\r\n");
    let (head, _) = split_response(&text);
    assert!(head.contains("403"), "必须拒绝非本机 Host：{}", head);

    // 缺少 Host 头同样拒绝
    let text = h.raw("GET /api/state HTTP/1.0\r\n\r\n");
    let (head, _) = split_response(&text);
    assert!(head.contains("403"));
}

#[test]
fn 跨站变更请求被拒绝() {
    let h = Harness::start();
    let text = h.raw(&format!(
        "POST /api/stop HTTP/1.0\r\nHost: {}\r\nOrigin: http://evil.example.com\r\nContent-Length: 2\r\n\r\n{{}}",
        h.addr()
    ));
    let (head, _) = split_response(&text);
    assert!(head.contains("403"), "必须拒绝跨站变更请求：{}", head);

    // 同源变更请求正常放行
    let text = h.raw(&format!(
        "POST /api/stop HTTP/1.0\r\nHost: {}\r\nOrigin: http://{}\r\nContent-Length: 2\r\n\r\n{{}}",
        h.addr(),
        h.addr()
    ));
    let (head, _) = split_response(&text);
    assert!(head.contains("200"), "同源请求不应被拦：{}", head);
}

#[test]
fn 安全拦截会写入日志() {
    let h = Harness::start();
    let _ = h.raw("GET /api/state HTTP/1.0\r\nHost: attacker.local\r\n\r\n");
    // 给日志线程一点时间落盘
    std::thread::sleep(Duration::from_millis(300));
    let text = std::fs::read_to_string(h.dir.join("test.log")).unwrap_or_default();
    assert!(
        text.contains("attacker.local"),
        "被拒绝的请求必须留下日志供排查，实际内容：{}",
        text
    );
}

#[test]
fn 停止服务后端口释放() {
    let mut h = Harness::start();
    let addr = h.addr();

    // 停止前可正常响应
    assert!(split_response(&h.get("/")).0.contains("200"));

    let mut server = h.take_server();
    server.stop();
    drop(server);

    // 服务停止后，新连接应立即被拒或建立后收不到任何数据
    if let Ok(mut stream) = TcpStream::connect(addr) {
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("设置超时失败");
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).unwrap_or(0);
        assert_eq!(n, 0, "服务已停止，不应再有响应");
    }
}
