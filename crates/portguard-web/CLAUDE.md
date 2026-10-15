# portguard-web 模块规范

## 职责
- 提供内嵌 Web 控制面板：编译期内嵌前端资源、纯函数路由、tiny_http 服务循环。
- `assets`：`include_str!` 把 `index.html` / `app.js` / `i18n.js` / `style.css` 打进 exe，实现单文件部署。`i18n.js` 是界面文案表（键 → `{zh, en}`），只被前端使用，后端不认识它。
- `router`：输入「方法 + 路径 + 查询串 + 请求体」输出 `Reply` 的纯函数，不接触 socket，可用 Mock API 完整单测。
- `server`：`WebServer` 起多线程服务循环并执行安全校验（Host / Origin / 请求体上限）。
- 不做什么：只通过 `portguard_core::api::PortGuardApi` 与业务交互，不认识抓包、防火墙与地理位置库内部结构（规范 18 UI/Core 解耦）；不含登录鉴权。

## 对外接口
- `DEFAULT_BIND: &str`：`"127.0.0.1:58080"`，直接取 `portguard_core::config::DEFAULT_PANEL_BIND`（同源，勿另写字面量）。
- `Reply`：`Json` / `Asset{mime, body}` / `NoContent` / `Error{status, message}`；`json`、`from_serializable`、`bad_request`、`status()`、`body()`。
- `PanelMeta`：`version` / `log_file` / `data_dir` / `started_at_ms` / `system_language`，面板运行期元信息；`system_language` 是启动时由 `portguard_win::system_language()` 探测一次的服务器界面语言（`"en"` 之外一律按中文），只在配置的 `panel.language` 为 `auto` 时用来决定界面文案。
- `allowed_hosts(bind) -> Vec<String>` / `host_allowed(host, bind) -> bool`：回环 Host 白名单与判定。
- `handle(api, meta, method, path, query, body) -> Reply`：路由入口。
- `WebServer`：`start(api, meta, bind, logger) -> Result<WebServer>`、`addr() -> &str`、`stop()`。
- `assets::ASSETS` / `INDEX_HTML` / `lookup(path)` / `total_bytes()`：内嵌资源访问。
- 路由接口：`GET /api/state|status|connections|bans|config|adapters|logs|events|meta`（`meta` 额外下发解析后的 `language`，供前端决定界面文案）；`POST /api/start|stop|ban|unban|lists/add|lists/remove|adapter|protection|config`。

## 关键约束
- **只监听回环**：默认 `127.0.0.1:58080`，面板无登录口令，安全完全依赖网络位置与请求头。
- **Host 校验**：`host_allowed` 只放行 `bind` / `127.0.0.1` / `localhost` / `[::1]` 且端口必须一致，阻断 DNS rebinding；缺失 Host 或非本机 Host 一律 403 并写日志。
- **Origin 校验**：仅对变更类（POST）请求，`origin_is_local` 比较主机与端口，拒绝跨站表单提交。
- **请求体上限**：`MAX_BODY = 1 MiB`，超限或未声明长度时用 `take` 限制实际读取量，防御超大请求撑爆内存；错误以 `{"error":"中文说明"}` 返回。
- **前端数据必须经 textContent 写入**：`app.js` 禁止用 `innerHTML` 拼接来自接口的数据，防 XSS（`assets.rs` 测试守住该约定）；地理位置文本同样按外部数据对待。
- **概览必须显示判定明细**：`status.stats.ignored` 的五项计数渲染到 `#ignore-stats`，是排查「端口无记录」的第一入口；「受保护端口」卡片副标 `#stat-ports-foot` 必须列出三组实际端口，不能只给总数（三组全空时显示提示文案）。
- **概览必须显示抓包观测**：`status.observed` 渲染到 `#tbody-observe`（方向 / 协议 / 本机端口 / 标志 / 包数，最多 12 行），回答「这个端口的包到底有没有被收到」；`status.parse_errors` / `parse_samples` 渲染到 `#parse-note`，用于区分「没抓到」与「解析器丢了」，`count_accept` 打开时同一行要说明当前按 SYN+ACK 统计。空态文案必须区分「保护未启动」与「还没抓到任何包」。
- **设置页必须有连接事件来源开关**：`#cfg-count-accept` 读写 `protect.count_accept`（**默认勾选**），说明文字指向概览页的抓包观测；`collectSettings` 必须把它写回配置对象，否则用户改了会被静默丢弃（历史上保护端口曾因同类问题被包成对象导致请求体解析失败）。
- **端口与名单的备注网格**：设置页三组保护端口与白/黑名单下方各有一张 `div.note-grid`（名单两张是静态挂载点 `#notes-whitelist` / `#notes-blacklist`，端口三张由脚本按 `PROTECT_GROUPS` 拼 `#notes-<key>`），按当前端口 / 规则逐条渲染备注输入框。网格随输入框内容实时重建（只重建网格容器，输入框本身不重渲染，焦点不丢），未保存的输入靠客户端 `noteCache` 保住；`collectSettings` **必须写回** `protect[*].notes` 与 `lists.notes`，漏掉会被后端按字段默认值当成空表、把用户备注清掉（与 `count_accept` 同类的历史故障）。备注是纯展示元数据，前端不得据此改变任何判定相关的展示口径。
- **备注内联展示**：`ConnectionView` / `BanView` 的 `port_note` / `ip_note` 由后端下发，前端只做内联灰字显示（`.note-tag`），无备注时不占位；概览「受保护端口」脚注按 `TCP 3389(远程桌面),22(跳板机)` 的形式带上备注。备注文本一律经 `textContent` 写入。
- **当前连接表只有「连接次数 / 阈值」一列**：`ConnectionView.count` 即**累计**连接次数（判定用的就是它），带 `count/threshold` 进度条与 `title` 提示；不得再加回「窗口次数」或单独的「累计」列——两者数值相同，并列只会让人误以为存在两套口径。
- **地理位置列是纯展示**：`ConnectionView.location` / `BanView.location` 只渲染，不参与筛选以外的任何逻辑；筛选框对 `location` 做子串匹配便于按地区查找。
- **数据表页必须撑满视口剩余高度**：`当前连接 / 封停列表 / 运行日志` 三页的 `section` 带 `fill` 类，`.app` 定高 100vh 且 `main` 独占滚动，卡片与 `.table-wrap` / `.logs` 沿 flex 链条逐级 `min-height: 0` 撑满高度，滚动条落在数据区内部；**禁止再用「视口高度减固定像素常量」估算表体高度**，该常量与实际顶栏不符时会出现「只显示几行 + 页面底部大片空白」（`assets.rs::数据表页撑满视口高度` 守住该约定）。概览 / 设置页按内容高度排布，由 `main` 整页滚动。
- **导航必须横排在顶部**：`index.html` 不设侧边栏，五个页面入口与「开始 / 停止 / 刷新」同处 `.topbar`（品牌 + 导航 + 操作一行，状态 chips + 版本一行）；窄屏（≤900px）导航换到第二行并横向滚动，操作按钮始终靠右。竖排侧边栏会吃掉约 250px 宽度，笔记本上看全连接表 / 封停表必须横向拖动（`assets.rs::导航位于顶部横排且无侧边栏` 守住该约定）。
- **资源内嵌单 exe**：前端经 `include_str!` 进二进制，改前端必须重编译；静态资源响应带 `no-cache`，避免升级后浏览器仍用旧前端。
- **界面语言只覆盖面板文案**：`/api/meta` 每次请求按当前配置解析 `panel.language`（`auto` → `meta.system_language`，取不到按中文），因此**保存语言设置即刻生效、无需重启**。英文模式只翻译面板界面文字：后端下发的事件流消息、运行日志、`parse_samples`、错误说明仍是中文，前端不得为它们再写一份英文（概览页的「最近事件」卡片要说明这一点）。前端约定：`index.html` 的静态文案一律带 `data-i18n` / `data-i18n-ph` / `data-i18n-title`（节点内含子元素时只把纯文字包进 `<span data-i18n>`，否则 `textContent` 会吃掉 badge 等子节点），`app.js` 里面向用户的文字一律经 `t(key, params)` 取，**禁止再写死中文**；文案键必须中英成对，新增界面文案却漏一份的表现是「切到英文后那一块还是中文」，界面上看不出是漏了，由 `assets.rs::界面语言资源内嵌且文案成对` 静态扫描守住（首页键 + 脚本里所有 `t("…")` 字面量都必须在 `i18n.js` 里有 zh 与 en）。**切换语言只能刷新文案，不得重建设置页表单**：`applyLanguage()` 走 `retranslateSettings()` 原地改文字（`renderSettings()` 是从 `state.config` 重建整张表单，会把用户正在编辑、还没保存的端口 / 名单 / 备注输入冲掉，与「改一处丢一处」的历史故障同类）。设置页下拉框改动后先按未保存的选择预览（`state.langPreview`），保存成功或放弃修改时作废并回到磁盘配置。
- **参数错误返回 400、服务端问题返回 500**：`map_error` 将 `InvalidIpRule` / `Config` 归为 400；`limit` 参数按区间夹取，未知接口 404。
- **路由层是纯函数**：不在其中做阻塞 I/O；响应头附加失败只跳过该可选头，不丢弃已生成的数据。
- > 待办：规范 0.2「UI 硬性约束」要求使用原生 Win32 API / Windows Controls 构建界面，本 crate 采用浏览器访问的 HTTP Web 面板，与该条要求存在偏差（未使用 WebView/Electron/Tauri，但亦非原生控件）。

## 测试
- 位置：内联 `#[cfg(test)] mod tests`（`assets.rs` / `router.rs` / `server.rs` / `testapi.rs`），以及独立的端到端测试文件 `src/e2e.rs`（`#[cfg(test)] mod e2e`），真实监听回环端口用裸 TCP 发请求（含 Host / Origin 精确控制）。
- 关键用例：`首页包含关键挂载点` / `导航位于顶部横排且无侧边栏` / `数据表页撑满视口高度` / `设置页提供端口与名单备注挂载点` / `界面语言资源内嵌且文案成对` / `脚本不使用危险的内联写入`、`主机校验只接受回环` / `限制参数被正确夹取`、`来源判定只认同机`、`白名单地址无法被封停` / `加入白名单会立即解封`、`陌生主机头被拒绝` / `跨站变更请求被拒绝` / `安全拦截会写入日志`、`封停与解封链路生效` / `非法配置被拒绝且不落盘` / `停止服务后端口释放`、`首页与静态资源可访问`（含判定明细容器与端口明细脚注）/ `保护端口全空必须被拒绝`、`端口与名单备注随配置往返并可展示` / `界面语言随设置切换且无需重启`（`auto` 跟随服务器系统语言、显式 `zh` / `en` 覆盖、再回 `auto` 仍跟系统、非法值被规范化为 `auto`）。
- 测试数量：39 个 `#[test]`（assets 8、router 6、server 3、testapi 7、e2e 15）。

## 依赖关系
- 依赖：`portguard-core`（`api::PortGuardApi`、`config::Config`、`error`、`model`、`logging`）、`portguard-storage`（`Logger`）、`tiny_http`（`=0.12.0`）、`serde` / `serde_json`。
- 被依赖：`portguard-app`（启动面板、提供 `PanelMeta` 与 `PortGuardApi` 实现）。
