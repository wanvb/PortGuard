//! 内嵌 HTTP 服务器。
//!
//! 选型 `tiny_http`：单一依赖、纯 Rust、不引入异步运行时，
//! 在 Win7 上无额外系统依赖，编译产物小。
//!
//! 安全边界（本程序没有登录口令，因此必须靠网络位置与请求头把关）：
//! 1. **只监听配置指定的回环地址**，默认 `127.0.0.1:58080`；
//! 2. **校验 Host 头**，阻断 DNS rebinding：攻击者可以让自己的域名
//!    解析到 127.0.0.1，再诱导浏览器访问本地面板执行封停/解封；
//! 3. **校验 Origin 头**（变更类请求），阻断跨站表单提交；
//! 4. **限制请求体大小**，防止恶意的超大请求把内存吃满。

use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use portguard_core::api::PortGuardApi;
use portguard_core::error::{AppError, Result};
use portguard_storage::Logger;
use tiny_http::{Header, Method, Request, Response, Server};

use crate::router::{self, PanelMeta, Reply};

/// 请求体上限：配置里最大的字段是名单，1 MiB 足够且不至于被撑爆内存。
const MAX_BODY: usize = 1024 * 1024;

/// 工作线程数。面板是单用户场景，少量线程即可避免一个慢请求阻塞整站。
const WORKERS: usize = 3;

/// 运行中的 Web 服务。
pub struct WebServer {
    addr: String,
    stop: Arc<AtomicBool>,
    server: Arc<Server>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

impl WebServer {
    /// 启动服务。`bind` 形如 `127.0.0.1:58080`。
    pub fn start(
        api: Arc<dyn PortGuardApi>,
        meta: PanelMeta,
        bind: &str,
        logger: Arc<Logger>,
    ) -> Result<WebServer> {
        let server = Server::http(bind).map_err(|e| {
            AppError::Web(format!("无法监听 {}：{}（端口可能已被占用）", bind, e))
        })?;

        let addr = format!("{}", server.server_addr());
        let stop = Arc::new(AtomicBool::new(false));
        let server = Arc::new(server);
        let mut workers = Vec::with_capacity(WORKERS);

        for i in 0..WORKERS {
            let server = Arc::clone(&server);
            let api = Arc::clone(&api);
            let meta = meta.clone();
            let logger = Arc::clone(&logger);
            let stop = Arc::clone(&stop);
            // 用实际监听地址而不是请求的绑定串：bind 传 0 时端口由系统分配，
            // Host 校验必须按真实端口比对，否则所有请求都会被当成伪造。
            let allowed_host = addr.clone();

            let handle = std::thread::Builder::new()
                .name(format!("portguard-web-{}", i))
                .spawn(move || {
                    worker_loop(server, api, meta, allowed_host, logger, stop);
                })
                .map_err(|e| AppError::Web(format!("创建 Web 工作线程失败：{}", e)))?;
            workers.push(handle);
        }

        logger.info(format!("控制面板已启动：http://{}", addr));
        Ok(WebServer {
            addr,
            stop,
            server,
            workers,
        })
    }

    /// 实际监听地址（`bind` 传 0 时端口由系统分配，需用这里的值）。
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// 停止服务并等待工作线程退出。
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // unblock 让阻塞在 recv() 上的线程立即返回
        self.server.unblock();
        for h in self.workers.drain(..) {
            let _ = h.join();
        }
    }
}

impl Drop for WebServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn worker_loop(
    server: Arc<Server>,
    api: Arc<dyn PortGuardApi>,
    meta: PanelMeta,
    bind: String,
    logger: Arc<Logger>,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::SeqCst) {
        let request = match server.recv_timeout(Duration::from_millis(300)) {
            Ok(Some(r)) => r,
            Ok(None) => continue,
            // 连接层错误（客户端断开等）不该终止服务
            Err(_) => continue,
        };
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let _ = handle_request(request, api.as_ref(), &meta, &bind, &logger);
    }
}

/// 处理单个请求：先做安全校验，再交给路由。
fn handle_request(
    mut request: Request,
    api: &dyn PortGuardApi,
    meta: &PanelMeta,
    bind: &str,
    logger: &Logger,
) -> std::io::Result<()> {
    let method = match request.method() {
        Method::Get => "GET",
        Method::Head => "HEAD",
        Method::Post => "POST",
        _ => "OTHER",
    };

    let url = request.url().to_string();
    let (path, query) = split_url(&url);
    let is_mutation = method == "POST";

    // ---- 安全校验 ----
    let host = header_value(&request, "Host").unwrap_or_default();
    if !router::host_allowed(&host, bind) {
        logger.warn(format!(
            "拒绝来源不明的面板请求：Host={} {} {}（可能是 DNS rebinding 尝试）",
            if host.is_empty() { "(缺失)" } else { &host },
            method,
            path
        ));
        return respond(request, forbidden("Host 头不是本机地址，请求已拒绝"));
    }
    if is_mutation {
        if let Some(origin) = header_value(&request, "Origin") {
            if !origin_is_local(&origin, bind) {
                logger.warn(format!(
                    "拒绝跨站变更请求：Origin={} {}",
                    origin, path
                ));
                return respond(request, forbidden("跨站请求已被拒绝"));
            }
        }
    }

    // ---- 读取请求体 ----
    let body = if is_mutation {
        match request.body_length() {
            Some(n) if n > MAX_BODY => {
                return respond(
                    request,
                    error_reply(413, &format!("请求体过大（{} 字节，上限 {}）", n, MAX_BODY)),
                )
            }
            _ => {
                let mut buf = String::new();
                // take 限制实际读取量，防御未声明长度的超大请求
                let limit = request.body_length().unwrap_or(MAX_BODY).min(MAX_BODY);
                let _ = request
                    .as_reader()
                    .take(limit as u64 + 1)
                    .read_to_string(&mut buf);
                buf
            }
        }
    } else {
        String::new()
    };

    let reply = router::handle(api, meta, method, path, query, &body);
    if reply.status() >= 400 {
        logger.debug(format!(
            "面板请求 {} {} → {}：{}",
            method,
            path,
            reply.status(),
            reply.body()
        ));
    }
    respond(request, reply)
}

/// 把路由结果写成 HTTP 响应。
fn respond(request: Request, reply: Reply) -> std::io::Result<()> {
    match reply {
        Reply::NoContent => request.respond(Response::empty(204)),
        Reply::Json(body) => request.respond(with_header(
            Response::from_string(body).with_status_code(200),
            "Content-Type",
            JSON_MIME,
        )),
        Reply::Asset { mime, body } => {
            // no-cache：每次都要回源校验，避免升级程序后浏览器仍用旧前端
            let resp = with_header(
                Response::from_string(body).with_status_code(200),
                "Content-Type",
                mime,
            );
            request.respond(with_header(resp, "Cache-Control", "no-cache"))
        }
        Reply::Error { status, message } => {
            let body = serde_json::json!({ "error": message }).to_string();
            request.respond(with_header(
                Response::from_string(body).with_status_code(status),
                "Content-Type",
                JSON_MIME,
            ))
        }
    }
}

fn forbidden(message: &str) -> Reply {
    error_reply(403, message)
}

fn error_reply(status: u16, message: &str) -> Reply {
    Reply::Error {
        status,
        message: message.to_string(),
    }
}

/// JSON 响应的 Content-Type。
const JSON_MIME: &str = "application/json; charset=utf-8";

/// 附加响应头。
///
/// 头名与头值都是编译期常量或已校验的 MIME 串，本不会失败；
/// 万一失败就跳过该头，而不是让整个请求失败（规范 26.1：不得假装成功，
/// 但也不该因为一个可选响应头把已生成的数据丢掉）。
fn with_header<R: Read>(resp: Response<R>, name: &str, value: &str) -> Response<R> {
    match Header::from_bytes(name.as_bytes(), value.as_bytes()) {
        Ok(h) => resp.with_header(h),
        Err(_) => resp,
    }
}

/// 取请求头（不区分大小写）。
fn header_value(request: &Request, name: &str) -> Option<String> {
    request
        .headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str().to_string())
}

/// 拆分 `路径?查询串`。
fn split_url(url: &str) -> (&str, &str) {
    match url.find('?') {
        Some(i) => (&url[..i], &url[i + 1..]),
        None => (url, ""),
    }
}

/// Origin 是否来自本机（只比较主机部分，端口必须一致）。
fn origin_is_local(origin: &str, bind: &str) -> bool {
    let host = origin
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    router::host_allowed(host, bind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 拆分路径与查询串() {
        assert_eq!(split_url("/a/b"), ("/a/b", ""));
        assert_eq!(split_url("/api/logs?limit=10"), ("/api/logs", "limit=10"));
        assert_eq!(split_url("/x?"), ("/x", ""));
    }

    #[test]
    fn 来源判定只认同机() {
        let bind = "127.0.0.1:58080";
        assert!(origin_is_local("http://127.0.0.1:58080", bind));
        assert!(origin_is_local("http://localhost:58080", bind));
        assert!(!origin_is_local("http://evil.example.com", bind));
        assert!(!origin_is_local("null", bind));
    }

    #[test]
    fn 响应头名可正确比较() {
        // 取值逻辑依赖 equiv 的大小写不敏感语义
        let h = Header::from_bytes(&b"Content-Type"[..], &b"text/plain"[..]).unwrap();
        assert!(h.field.equiv("content-type"));
        assert!(!h.field.equiv("host"));
    }
}
