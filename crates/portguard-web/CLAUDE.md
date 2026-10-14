# portguard-web 模块规范

## 职责
- 提供内嵌 Web 控制面板：编译期内嵌前端资源、纯函数路由、tiny_http 服务循环。
- `assets`：`include_str!` 把 `index.html` / `app.js` / `style.css` 打进 exe，实现单文件部署。
- `router`：输入「方法 + 路径 + 查询串 + 请求体」输出 `Reply` 的纯函数，不接触 socket，可用 Mock API 完整单测。
- `server`：`WebServer` 起多线程服务循环并执行安全校验（Host / Origin / 请求体上限）。
- 不做什么：只通过 `portguard_core::api::PortGuardApi` 与业务交互，不认识抓包与防火墙内部结构（规范 18 UI/Core 解耦）；不含登录鉴权。

## 对外接口
- `DEFAULT_BIND: &str`：`"127.0.0.1:18080"`。
- `Reply`：`Json` / `Asset{mime, body}` / `NoContent` / `Error{status, message}`；`json`、`from_serializable`、`bad_request`、`status()`、`body()`。
- `PanelMeta`：`version` / `log_file` / `data_dir` / `started_at_ms`，面板运行期元信息。
- `allowed_hosts(bind) -> Vec<String>` / `host_allowed(host, bind) -> bool`：回环 Host 白名单与判定。
- `handle(api, meta, method, path, query, body) -> Reply`：路由入口。
- `WebServer`：`start(api, meta, bind, logger) -> Result<WebServer>`、`addr() -> &str`、`stop()`。
- `assets::ASSETS` / `INDEX_HTML` / `lookup(path)` / `total_bytes()`：内嵌资源访问。
- 路由接口：`GET /api/state|status|connections|bans|config|adapters|logs|events|meta`；`POST /api/start|stop|ban|unban|lists/add|lists/remove|adapter|protection|config`。

## 关键约束
- **只监听回环**：默认 `127.0.0.1:18080`，面板无登录口令，安全完全依赖网络位置与请求头。
- **Host 校验**：`host_allowed` 只放行 `bind` / `127.0.0.1` / `localhost` / `[::1]` 且端口必须一致，阻断 DNS rebinding；缺失 Host 或非本机 Host 一律 403 并写日志。
- **Origin 校验**：仅对变更类（POST）请求，`origin_is_local` 比较主机与端口，拒绝跨站表单提交。
- **请求体上限**：`MAX_BODY = 1 MiB`，超限或未声明长度时用 `take` 限制实际读取量，防御超大请求撑爆内存；错误以 `{"error":"中文说明"}` 返回。
- **前端数据必须经 textContent 写入**：`app.js` 禁止用 `innerHTML` 拼接来自接口的数据，防 XSS（`assets.rs` 测试守住该约定）。
- **资源内嵌单 exe**：前端经 `include_str!` 进二进制，改前端必须重编译；静态资源响应带 `no-cache`，避免升级后浏览器仍用旧前端。
- **参数错误返回 400、服务端问题返回 500**：`map_error` 将 `InvalidIpRule` / `Config` 归为 400；`limit` 参数按区间夹取，未知接口 404。
- **路由层是纯函数**：不在其中做阻塞 I/O；响应头附加失败只跳过该可选头，不丢弃已生成的数据。
- > 待办：规范 0.2「UI 硬性约束」要求使用原生 Win32 API / Windows Controls 构建界面，本 crate 采用浏览器访问的 HTTP Web 面板，与该条要求存在偏差（未使用 WebView/Electron/Tauri，但亦非原生控件）。

## 测试
- 位置：内联 `#[cfg(test)] mod tests`（`assets.rs` / `router.rs` / `server.rs` / `testapi.rs`），以及独立的端到端测试文件 `src/e2e.rs`（`#[cfg(test)] mod e2e`），真实监听回环端口用裸 TCP 发请求（含 Host / Origin 精确控制）。
- 关键用例：`首页包含关键挂载点` / `脚本不使用危险的内联写入`、`主机校验只接受回环` / `限制参数被正确夹取`、`来源判定只认同机`、`白名单地址无法被封停` / `加入白名单会立即解封`、`陌生主机头被拒绝` / `跨站变更请求被拒绝` / `安全拦截会写入日志`、`封停与解封链路生效` / `非法配置被拒绝且不落盘` / `停止服务后端口释放`。
- 测试数量：32 个 `#[test]`（assets 4、router 6、server 3、testapi 7、e2e 12）。

## 依赖关系
- 依赖：`portguard-core`（`api::PortGuardApi`、`config::Config`、`error`、`model`、`logging`）、`portguard-storage`（`Logger`）、`tiny_http`（`=0.12.0`）、`serde` / `serde_json`。
- 被依赖：`portguard-app`（启动面板、提供 `PanelMeta` 与 `PortGuardApi` 实现）。
