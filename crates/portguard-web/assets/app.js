/* ============================================================
   PortGuard 控制面板前端逻辑
   纯 ES6 + fetch，无框架、无构建步骤。

   安全约定：所有来自接口的数据一律用 textContent 写入 DOM，
   绝不用 innerHTML 拼接，避免把日志/客户端名里的内容当作 HTML 执行。
   ============================================================ */

"use strict";

/* ---------------- 基础工具 ---------------- */

const $ = (id) => document.getElementById(id);

/** 创建元素并设置属性 / 子节点。 */
function el(tag, props, children) {
  const node = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else if (k === "html") node.innerHTML = v; // 仅用于内置常量
      else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
      else if (v !== null && v !== undefined) node.setAttribute(k, v);
    }
  }
  for (const c of children || []) {
    if (c === null || c === undefined) continue;
    node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
}

/** 补零。 */
const pad = (n) => String(n).padStart(2, "0");

/** Unix 毫秒 → 本地时间字符串。时间戳为 0 时返回 "-"。 */
function fmtTime(ms) {
  if (!ms) return "-";
  const d = new Date(ms);
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
  );
}

/** 仅时分秒，用于高密度表格。 */
function fmtClock(ms) {
  if (!ms) return "-";
  const d = new Date(ms);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

/** 秒 → 人类可读时长。 */
function fmtDuration(seconds) {
  if (seconds === null || seconds === undefined) return "永久";
  let s = Math.max(0, Math.floor(seconds));
  const d = Math.floor(s / 86400);
  s %= 86400;
  const h = Math.floor(s / 3600);
  s %= 3600;
  const m = Math.floor(s / 60);
  s %= 60;
  if (d > 0) return `${d} 天 ${h} 小时`;
  if (h > 0) return `${h} 小时 ${m} 分`;
  if (m > 0) return `${m} 分 ${s} 秒`;
  return `${s} 秒`;
}

function fmtNumber(n) {
  return (n === null || n === undefined ? 0 : n).toLocaleString("zh-CN");
}

/* ---------------- 提示与确认 ---------------- */

function toast(message, kind) {
  const box = $("toasts");
  const node = el("div", { class: "toast " + (kind || ""), text: message });
  box.appendChild(node);
  setTimeout(() => node.remove(), 4200);
}

/** Promise 化的确认对话框。 */
function confirmDialog(title, text, okLabel) {
  return new Promise((resolve) => {
    const modal = $("modal");
    $("modal-title").textContent = title;
    $("modal-text").textContent = text;
    $("modal-ok").textContent = okLabel || "确认";
    modal.classList.remove("hidden");

    const done = (result) => {
      modal.classList.add("hidden");
      $("modal-ok").removeEventListener("click", onOk);
      $("modal-cancel").removeEventListener("click", onCancel);
      resolve(result);
    };
    const onOk = () => done(true);
    const onCancel = () => done(false);
    $("modal-ok").addEventListener("click", onOk);
    $("modal-cancel").addEventListener("click", onCancel);
  });
}

/* ---------------- 接口调用 ---------------- */

async function apiGet(path) {
  const res = await fetch(path, { cache: "no-store" });
  const text = await res.text();
  if (!res.ok) throw new Error(describeHttpError(res.status, text));
  return text ? JSON.parse(text) : null;
}

async function apiPost(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(describeHttpError(res.status, text));
  return text ? JSON.parse(text) : null;
}

/** 把服务端返回的错误体转成中文提示。 */
function describeHttpError(status, text) {
  try {
    const body = JSON.parse(text);
    if (body && body.error) return body.error;
  } catch (_) {
    /* 非 JSON 响应，退回到原始文本 */
  }
  return text ? `请求失败（${status}）：${text}` : `请求失败（HTTP ${status}）`;
}

/** 统一的动作包装：失败弹提示，成功提示 + 立即刷新。 */
async function run(fn, okMessage) {
  try {
    await fn();
    if (okMessage) toast(okMessage, "ok");
    await refreshState();
    return true;
  } catch (e) {
    toast(e.message || String(e), "err");
    return false;
  }
}

/* ---------------- 全局状态 ---------------- */

const state = {
  status: null,
  connections: [],
  bans: [],
  events: [],
  config: null,
  adapters: [],
  logs: [],
  page: "overview",
  stateTimer: null,
  logTimer: null,
};

const QUICK_SWITCHES = [
  { key: "risky_ports", field: "risky_ports", title: "危险端口保护", hint: "拦截 135/137/138/139/445" },
  { key: "block_icmp", field: "block_icmp", title: "禁止 Ping", hint: "丢弃 ICMP Echo 请求" },
  { key: "autostart", field: "autostart", title: "开机自动启动", hint: "注册计划任务，开机即防护" },
  { key: "rdp_guard", field: "rdp_enabled", title: "远程桌面保护", hint: "按客户端计算机名放行" },
];

/* ---------------- 渲染：顶部状态 ---------------- */

function renderStatus() {
  const s = state.status;
  if (!s) return;

  const runDot = $("chip-run-dot");
  runDot.className = "dot " + (s.running ? "on" : "off");
  $("chip-run").textContent = s.running ? "保护中" : "已停止";

  $("chip-adapter").textContent = s.adapter || "未选择";
  $("chip-ip").textContent = s.local_ip || "-";

  const adminDot = $("chip-admin-dot");
  adminDot.className = "dot " + (s.admin ? "on" : "warn");
  $("chip-admin").textContent = s.admin ? "管理员" : "权限不足";

  $("chip-uptime").textContent = fmtDuration(s.stats.uptime_seconds);

  $("stat-tracking").textContent = fmtNumber(s.stats.tracking);
  $("stat-banned").textContent = fmtNumber(s.stats.banned);
  $("stat-banned-foot").textContent = `其中永久 ${fmtNumber(s.stats.permanent)}`;
  $("stat-ports").textContent = fmtNumber(s.protected_ports);
  $("stat-ports-foot").textContent = protectedPortsText(s);
  $("stat-packets").textContent = fmtNumber(s.stats.captured_packets);
  $("stat-packets-foot").textContent = `累计封停 ${fmtNumber(s.stats.total_bans)} 次`;
  renderIgnoreStats(s);
  renderParseNote(s);
  renderObserve(s);

  $("foot-version").textContent = `PortGuard v${s.version}`;
  $("badge-connections").textContent = state.connections.length;
  $("badge-bans").textContent = state.bans.length;

  $("btn-start").disabled = s.running;
  $("btn-stop").disabled = !s.running;

  // 地理位置库状态：加载成功给出路径，否则给出原因与放置位置
  const geoTip = $("geo-status");
  if (geoTip) {
    const text = s.geo_status || "";
    geoTip.textContent = s.geo_ready ? `已加载：${text}` : text;
    geoTip.className = s.geo_ready ? "muted" : "muted warn";
  }

  // 权限不足时给出明确后果提示，而不是等到封停失败
  if (!s.admin && !state.adminWarned) {
    state.adminWarned = true;
    toast("未以管理员身份运行：抓包与防火墙操作会失败，请重新以管理员身份启动", "warn");
  }
}

/** 受保护端口明细：把三组端口直接写进卡片脚注，避免只看到一个总数。
 *
 *  配置尚未取到时退回固定文案（概览页首屏）。 */
function protectedPortsText(s) {
  const protect = state.config && state.config.protect;
  if (!protect) return "TCP / TCP-WEB / UDP 合计";
  const fmt = (g) => {
    const ports = (protect[g] && protect[g].ports) || [];
    return ports.length ? ports.join(",") : "未设置";
  };
  if (!s.protected_ports) return "三组均未设置，不会统计与封停";
  return `TCP ${fmt("tcp")} · WEB ${fmt("http")} · UDP ${fmt("udp")}`;
}

/** 判定明细：抓包数在涨但连接列表空着时，用这几项区分问题出在哪一层。 */
function renderIgnoreStats(s) {
  const box = $("ignore-stats");
  if (!box || !s.stats) return;
  const ig = s.stats.ignored || {};
  const items = [
    { label: "非本机流量", value: ig.not_local, hint: "混杂模式抓到的同网段其它主机流量" },
    { label: "本机外连", value: ig.outbound, hint: "本机主动发起，默认不计入阈值" },
    { label: "非新建连接", value: ig.not_new_connection, hint: "SYN+ACK、纯 ACK、FIN 等过程包" },
    { label: "端口未保护", value: ig.port_not_protected, hint: "端口不在 TCP / WEB / UDP 三组内" },
    { label: "ICMP", value: ig.icmp, hint: "只由系统级「禁止 Ping」处理" },
  ];
  box.textContent = "";
  for (const it of items) {
    box.appendChild(
      el("div", { class: "stat" }, [
        el("div", { class: "stat-label", text: it.label }),
        el("div", { class: "stat-value", text: fmtNumber(it.value || 0) }),
        el("div", { class: "stat-foot", text: it.hint }),
      ])
    );
  }
}

/** 解析失败说明：区分「没抓到」与「抓到但解析器丢了」。 */
function renderParseNote(s) {
  const box = $("parse-note");
  if (!box) return;
  const errs = s.parse_errors || 0;
  const samples = s.parse_samples || [];
  let text = errs
    ? `解析失败的包 ${fmtNumber(errs)} 个（非 IPv4 / 分片 / 畸形包）`
    : "解析失败的包 0 个";
  if (s.count_accept) {
    text += "；当前按「服务端握手响应（SYN+ACK）」统计连接事件";
  }
  if (samples.length) {
    text += `。样本：${samples.join(" | ")}`;
  }
  box.textContent = text;
}

/** 抓包观测表：混杂模式实际收到了哪些包，按次数排序。 */
function renderObserve(s) {
  const body = $("tbody-observe");
  if (!body) return;
  body.textContent = "";
  const rows = s.observed || [];
  if (!rows.length) {
    body.appendChild(
      el("tr", {}, [
        el("td", { colspan: "5" }, [
          el("div", { class: "empty" }, [
            el("strong", { text: s.running ? "还没抓到任何包" : "保护未启动" }),
            el("span", {
              text: s.running
                ? "先发起一次连接，再回来看这里出现了哪个端口"
                : "点击「开始保护」后才能看到实际抓到的包",
            }),
          ]),
        ]),
      ])
    );
    return;
  }
  for (const o of rows) {
    const row = el("tr");
    row.appendChild(el("td", {}, [el("span", { class: "badge group", text: o.direction })]));
    row.appendChild(el("td", { class: "mono", text: o.protocol }));
    row.appendChild(el("td", { class: "mono", text: String(o.port) }));
    row.appendChild(el("td", { class: "mono", text: o.flags }));
    row.appendChild(el("td", { class: "mono", text: fmtNumber(o.count) }));
    body.appendChild(row);
  }
}

/* ---------------- 渲染：概览快捷开关 ---------------- */

function renderQuickSwitches() {
  const box = $("quick-switches");
  if (!box || !state.status) return;
  const s = state.status;
  box.textContent = "";

  for (const item of QUICK_SWITCHES) {
    const on = !!s[item.field];
    const input = el("input", {
      type: "checkbox",
      onchange: async (ev) => {
        const enabled = ev.target.checked;
        ev.target.disabled = true;
        await run(
          () => apiPost("/api/protection", { key: item.key, enabled }),
          `${item.title}已${enabled ? "开启" : "关闭"}`
        );
        ev.target.disabled = false;
      },
    });
    input.checked = on;
    box.appendChild(
      el("label", { class: "switch" }, [
        input,
        el("span", { class: "switch-text" }, [
          el("b", { text: item.title }),
          el("span", { text: item.hint }),
        ]),
      ])
    );
  }
}

/* ---------------- 渲染：事件流 ---------------- */

function renderEvents() {
  const box = $("events");
  box.textContent = "";
  if (!state.events.length) {
    box.appendChild(
      el("div", { class: "empty" }, [
        el("strong", { text: "暂无事件" }),
        el("span", { text: "发生封停、解封或系统提示时会显示在这里" }),
      ])
    );
    return;
  }
  // 最新的排在最上面
  for (const e of state.events.slice(0, 60)) {
    box.appendChild(
      el("div", { class: "event" }, [
        el("span", { class: "event-time", text: fmtTime(e.ts_ms) }),
        el("span", { class: "event-kind " + kindClass(e.kind), text: e.kind.toUpperCase() }),
        el("span", { class: "event-msg", text: e.message }),
      ])
    );
  }
}

function kindClass(kind) {
  if (kind === "ban" || kind === "unban" || kind === "system" || kind === "warn") return kind;
  return "other";
}

/* ---------------- 渲染：连接表 ---------------- */

function renderConnections() {
  const body = $("tbody-connections");
  body.textContent = "";
  const keyword = ($("filter-connections").value || "").trim().toLowerCase();
  const rows = state.connections.filter((c) => {
    if (!keyword) return true;
    return (
      c.ip.toLowerCase().includes(keyword) ||
      (c.location || "").toLowerCase().includes(keyword) ||
      String(c.service_port).includes(keyword)
    );
  });

  if (!rows.length) {
    body.appendChild(
      el("tr", {}, [
        el("td", { colspan: "9" }, [
          el("div", { class: "empty" }, [
            el("strong", { text: keyword ? "没有匹配的记录" : "当前没有跟踪中的连接" }),
            el("span", {
              text: keyword ? "请调整筛选条件" : "抓到受保护端口的新连接请求后会出现在这里",
            }),
          ]),
        ]),
      ])
    );
    return;
  }

  for (const c of rows) {
    const ratio = c.threshold > 0 ? c.count / c.threshold : 0;
    const level = ratio >= 1 ? "danger" : ratio >= 0.6 ? "warn" : "";

    const row = el("tr", { class: c.whitelisted ? "whitelisted" : "" });
    row.appendChild(el("td", { class: "mono", text: c.ip }));
    row.appendChild(el("td", { class: "muted", text: c.location || "未知" }));
    row.appendChild(el("td", {}, [el("span", { class: "badge group", text: c.group })]));
    row.appendChild(el("td", { class: "mono", text: String(c.service_port) }));
    row.appendChild(
      el("td", {
        title: `累计连接 ${c.count} 次，达到阈值 ${c.threshold} 次即封停`,
      }, [
        el("div", { class: "meter" }, [
          el("div", { class: "meter-track" }, [
            el("div", {
              class: "meter-fill " + level,
              style: `width:${Math.min(100, Math.round(ratio * 100))}%`,
            }),
          ]),
          el("span", { class: "meter-text", text: `${c.count}/${c.threshold}` }),
        ]),
      ])
    );
    row.appendChild(el("td", { class: "mono muted", text: fmtClock(c.first_seen_ms) }));
    row.appendChild(el("td", { class: "mono", text: fmtClock(c.last_seen_ms) }));
    row.appendChild(el("td", {}, [stateBadge(c)]));
    // 已封停的行保留在列表中（状态 BANNED / PERMANENT），此时该给的是「解封」
    const banned = c.state === "BANNED" || c.state === "PERMANENT";
    row.appendChild(
      el("td", {}, [
        el("div", { class: "form-actions" }, [
          banned
            ? el("button", {
                class: "btn sm",
                text: "解封",
                onclick: () => unban(c.ip),
              })
            : el("button", {
                class: "btn sm danger",
                text: "封停",
                onclick: () => banIp(c.ip, true),
              }),
          el("button", {
            class: "btn sm",
            text: "加白名单",
            onclick: () => whitelistAdd(c.ip),
          }),
        ]),
      ])
    );
    body.appendChild(row);
  }
}

function stateBadge(c) {
  if (c.whitelisted || c.state === "WHITELIST") {
    return el("span", { class: "badge whitelist", text: "白名单" });
  }
  if (c.state === "PERMANENT") return el("span", { class: "badge permanent", text: "永久封停" });
  if (c.state === "BANNED") return el("span", { class: "badge banned", text: "已封停" });
  return el("span", { class: "badge tracking", text: "跟踪中" });
}

/* ---------------- 渲染：封停表 ---------------- */

function renderBans() {
  const body = $("tbody-bans");
  body.textContent = "";
  if (!state.bans.length) {
    body.appendChild(
      el("tr", {}, [
        el("td", { colspan: "10" }, [
          el("div", { class: "empty" }, [
            el("strong", { text: "封停列表为空" }),
            el("span", { text: "没有地址被拦截" }),
          ]),
        ]),
      ])
    );
    return;
  }

  for (const b of state.bans) {
    const row = el("tr", { class: "banned" });
    row.appendChild(el("td", { class: "mono", text: b.ip }));
    row.appendChild(el("td", { class: "muted", text: b.location || "未知" }));
    row.appendChild(el("td", { text: b.reason_label || b.reason }));
    row.appendChild(el("td", { class: "mono", text: b.protocol || "-" }));
    row.appendChild(
      el("td", { class: "mono", text: b.service_port ? String(b.service_port) : "-" })
    );
    row.appendChild(el("td", { class: "mono", text: fmtNumber(b.attempt_count) }));
    row.appendChild(el("td", { class: "mono muted", text: fmtTime(b.created_at_ms) }));
    row.appendChild(
      el("td", {
        class: "mono",
        text: b.permanent ? "永久" : fmtDuration(b.remaining_seconds),
      })
    );
    row.appendChild(el("td", { class: "mono muted", text: b.rule_name }));
    row.appendChild(
      el("td", {}, [
        el("div", { class: "form-actions" }, [
          el("button", { class: "btn sm", text: "解封", onclick: () => unban(b.ip) }),
          el("button", { class: "btn sm", text: "加白名单", onclick: () => whitelistAdd(b.ip) }),
        ]),
      ])
    );
    body.appendChild(row);
  }
}

/* ---------------- 渲染：日志 ---------------- */

function renderLogs() {
  const box = $("logs");
  const level = $("log-filter").value;
  const order = { trace: 0, debug: 1, info: 2, warn: 3, error: 4 };
  const min = level ? order[level] : 0;

  const rows = state.logs.filter((l) => order[l.level] >= min);
  box.textContent = "";
  for (const l of rows) {
    box.appendChild(
      el("div", { class: "log-line" }, [
        el("span", { class: "t", text: fmtTime(l.ts_ms) }),
        el("span", { class: "l " + l.level.toUpperCase(), text: l.level.toUpperCase() }),
        el("span", { text: l.message }),
      ])
    );
  }
  if (!rows.length) {
    box.appendChild(el("div", { class: "muted", text: "暂无日志" }));
  }
  if ($("log-autoscroll").checked) box.scrollTop = box.scrollHeight;
}

/* ---------------- 渲染：设置 ---------------- */

const PROTECT_GROUPS = [
  { key: "tcp", name: "TCP 保护端口", hint: "普通 TCP 服务" },
  { key: "http", name: "TCP-WEB 端口", hint: "Web 类服务，阈值可放宽" },
  { key: "udp", name: "UDP 保护端口", hint: "UDP 服务" },
];

function renderSettings() {
  const cfg = state.config;
  if (!cfg) return;

  $("cfg-bind").value = cfg.panel.bind;
  $("cfg-ban-duration").value = cfg.ban.duration_seconds;
  $("cfg-ban-permanent").checked = cfg.ban.permanent;
  $("cfg-whitelist").value = (cfg.lists.whitelist || []).join("\n");
  $("cfg-blacklist").value = (cfg.lists.blacklist || []).join("\n");
  $("cfg-rdp-enabled").checked = cfg.rdp.enabled;
  $("cfg-rdp-list").value = (cfg.rdp.client_whitelist || []).join("\n");
  $("cfg-log-level").value = cfg.logging.level;
  $("cfg-log-lines").value = cfg.logging.max_memory_lines;
  $("cfg-geo-enabled").checked = cfg.geo.enabled;
  $("cfg-geo-db").value = cfg.geo.db;
  $("cfg-count-accept").checked = !!cfg.protect.count_accept;

  // 保护端口三组
  const box = $("protect-rows");
  box.textContent = "";
  for (const g of PROTECT_GROUPS) {
    const rule = cfg.protect[g.key] || { ports: [], max_attempts: 5 };
    box.appendChild(
      el("div", { class: "port-row" }, [
        el("span", { class: "port-name", text: g.name }),
        el("input", {
          type: "text",
          value: (rule.ports || []).join(","),
          placeholder: "如 3389,22",
          "data-group": g.key,
          "data-field": "ports",
          title: g.hint,
        }),
        el("span", { class: "muted", text: "累计连接" }),
        el("input", {
          type: "number",
          min: "1",
          value: rule.max_attempts,
          "data-group": g.key,
          "data-field": "max_attempts",
          title: "累计连接次数达到该值即封停；该来源空闲 10 分钟后计数归零",
        }),
        el("span", { class: "muted", text: "次即封停" }),
      ])
    );
  }

  // 系统开关（与概览里的快捷开关等价，这里随配置一起保存）
  const sw = $("system-switches");
  sw.textContent = "";
  const sysItems = [
    { field: "risky_ports", title: "危险端口保护", hint: "135/137/138/139/445" },
    { field: "block_icmp", title: "禁止 Ping", hint: "丢弃 ICMP Echo 请求" },
    { field: "autostart", title: "开机自动启动", hint: "注册计划任务" },
  ];
  for (const item of sysItems) {
    const input = el("input", { type: "checkbox", "data-system": item.field });
    input.checked = !!cfg.system[item.field];
    sw.appendChild(
      el("label", { class: "switch" }, [
        input,
        el("span", { class: "switch-text" }, [
          el("b", { text: item.title }),
          el("span", { text: item.hint }),
        ]),
      ])
    );
  }

  renderAdapterOptions();
}

function renderAdapterOptions() {
  const select = $("cfg-adapter");
  const current = (state.config && state.config.network.adapter) || "";
  select.textContent = "";

  const usable = state.adapters.filter((a) => a.usable);
  if (!usable.length) {
    select.appendChild(
      el("option", { value: "", text: state.adapters.length ? "没有可用网卡" : "读取中…" })
    );
  }
  for (const a of usable) {
    const label = `${a.ip}${a.is_virtual ? "（虚拟）" : ""} · ${a.description}`;
    select.appendChild(el("option", { value: a.ip, text: label }));
  }
  select.value = current;
  if (select.value !== current && current) {
    // 配置里的网卡当前不在列表中（已拔网线等），保留为可选项以免保存时被清空
    select.appendChild(el("option", { value: current, text: `${current}（当前配置，未在列表）` }));
    select.value = current;
  }
}

/** 从表单收集配置对象（保留未在界面上暴露的字段）。 */
function collectSettings() {
  const base = JSON.parse(JSON.stringify(state.config));
  base.panel.bind = $("cfg-bind").value.trim();
  base.ban.duration_seconds = Number($("cfg-ban-duration").value) || 0;
  base.ban.permanent = $("cfg-ban-permanent").checked;
  base.lists.whitelist = splitLines($("cfg-whitelist").value);
  base.lists.blacklist = splitLines($("cfg-blacklist").value);
  base.rdp.enabled = $("cfg-rdp-enabled").checked;
  base.rdp.client_whitelist = splitLines($("cfg-rdp-list").value);
  base.logging.level = $("cfg-log-level").value;
  base.logging.max_memory_lines = Number($("cfg-log-lines").value) || 2000;
  base.geo.enabled = $("cfg-geo-enabled").checked;
  base.geo.db = $("cfg-geo-db").value.trim();

  const netAdapter = $("cfg-adapter").value;
  base.network.adapter = netAdapter;

  for (const g of PROTECT_GROUPS) {
    // collectPorts 返回 { ports, error }，只取 ports；整对象赋给后端会因
    // 「map 喂给 Vec<u16>」而报请求体格式错误
    base.protect[g.key].ports = collectPorts(g.key).ports;
    base.protect[g.key].max_attempts = collectNumber(g.key, "max_attempts");
  }

  base.protect.count_accept = $("cfg-count-accept").checked;

  for (const input of document.querySelectorAll("[data-system]")) {
    base.system[input.getAttribute("data-system")] = input.checked;
  }
  return base;
}

function splitLines(text) {
  return text
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * 解析端口输入。
 * 返回 { ports, error }：非法内容直接在前端拦下，避免把一个坏配置写进磁盘。
 */
function collectPorts(group) {
  const input = document.querySelector(`[data-group="${group}"][data-field="ports"]`);
  const parts = (input.value || "")
    .split(/[,，\s]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  const ports = [];
  for (const p of parts) {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 1 || n > 65535) {
      return { ports: null, error: `端口「${p}」非法：必须是 1-65535 之间的整数` };
    }
    ports.push(n);
  }
  return { ports, error: null };
}

function collectNumber(group, field) {
  const input = document.querySelector(`[data-group="${group}"][data-field="${field}"]`);
  return Number(input.value) || 1;
}

function showSettingsErrors(errors) {
  const box = $("settings-errors");
  box.textContent = "";
  const list = Array.isArray(errors) ? errors.filter(Boolean) : errors ? [errors] : [];
  if (!list.length) return;
  box.appendChild(
    el("div", { class: "errors" }, [
      el("b", { text: "保存失败" }),
      el("ul", {}, list.map((t) => el("li", { text: t }))),
    ])
  );
}

/* ---------------- 动作 ---------------- */

async function banIp(ip, permanent) {
  const ok = await confirmDialog(
    "封停地址",
    `确定要封停 ${ip} 吗？程序会为该地址创建一条防火墙入站拦截规则。`,
    "封停"
  );
  if (!ok) return;
  await run(() => apiPost("/api/ban", { ip, permanent }), `${ip} 已封停`);
}

async function unban(ip) {
  const ok = await confirmDialog(
    "解除封停",
    `确定要解除对 ${ip} 的封停并删除对应防火墙规则吗？`,
    "解封"
  );
  if (!ok) return;
  await run(() => apiPost("/api/unban", { ip }), `${ip} 已解封`);
}

async function whitelistAdd(ip) {
  const ok = await confirmDialog(
    "加入白名单",
    `${ip} 将被加入白名单并立即解封。白名单地址永远不会被自动或手动封停。`,
    "加入白名单"
  );
  if (!ok) return;
  await run(() => apiPost("/api/lists/add", { kind: "whitelist", rule: ip }), `${ip} 已加入白名单`);
}

/* ---------------- 数据刷新 ---------------- */

async function refreshState() {
  try {
    const data = await apiGet("/api/state");
    state.status = data.status;
    state.connections = data.connections;
    state.bans = data.bans;
    state.events = data.events;
    renderStatus();
    renderQuickSwitches();
    renderEvents();
    renderConnections();
    renderBans();
  } catch (e) {
    // 轮询失败只在控制台留痕，避免每 2 秒弹一次提示淹没界面
    console.warn("状态刷新失败：", e.message);
  }
}

async function refreshLogs() {
  if (state.page !== "logs") return;
  try {
    state.logs = await apiGet("/api/logs?limit=500");
    renderLogs();
  } catch (e) {
    console.warn("日志刷新失败：", e.message);
  }
}

async function refreshAdapters() {
  try {
    state.adapters = await apiGet("/api/adapters");
    if (state.page === "settings") renderAdapterOptions();
  } catch (e) {
    toast("读取网卡列表失败：" + e.message, "err");
  }
}

async function loadSettings() {
  try {
    showSettingsErrors(null);
    state.config = await apiGet("/api/config");
    await refreshAdapters();
    renderSettings();
  } catch (e) {
    showSettingsErrors(["读取配置失败：" + e.message]);
  }
}

/* ---------------- 页面切换 ---------------- */

function switchPage(page) {
  state.page = page;
  for (const btn of document.querySelectorAll(".nav-item")) {
    btn.classList.toggle("active", btn.getAttribute("data-page") === page);
  }
  for (const sec of document.querySelectorAll(".page")) {
    sec.classList.toggle("active", sec.id === "page-" + page);
  }
  if (page === "settings") loadSettings();
  if (page === "logs") refreshLogs();
}

/* ---------------- 事件绑定 ---------------- */

function bindEvents() {
  for (const btn of document.querySelectorAll(".nav-item")) {
    btn.addEventListener("click", () => switchPage(btn.getAttribute("data-page")));
  }

  $("btn-refresh").addEventListener("click", async () => {
    await refreshState();
    await refreshLogs();
  });

  $("btn-start").addEventListener("click", () =>
    run(() => apiPost("/api/start"), "已开始保护")
  );
  $("btn-stop").addEventListener("click", async () => {
    const ok = await confirmDialog(
      "停止保护",
      "停止后不再抓包，已有封停记录与防火墙规则会保留。确定要停止吗？",
      "停止保护"
    );
    if (ok) await run(() => apiPost("/api/stop"), "已停止保护");
  });

  $("btn-manual-ban").addEventListener("click", async () => {
    const ip = $("manual-ip").value.trim();
    if (!ip) {
      toast("请先填写要封停的 IP", "warn");
      return;
    }
    await banIp(ip, $("manual-permanent").checked);
    $("manual-ip").value = "";
  });

  $("filter-connections").addEventListener("input", renderConnections);
  $("log-filter").addEventListener("change", renderLogs);

  $("btn-adapters-refresh").addEventListener("click", refreshAdapters);
  $("btn-reload").addEventListener("click", () => {
    loadSettings();
    toast("已重新载入配置", "ok");
  });

  $("btn-save").addEventListener("click", async () => {
    showSettingsErrors(null);
    const errors = [];
    for (const g of PROTECT_GROUPS) {
      const r = collectPorts(g.key);
      if (r.error) errors.push(r.error);
    }
    if (errors.length) {
      showSettingsErrors(errors);
      toast("请先修正表单中的错误", "err");
      return;
    }

    const cfg = collectSettings();
    const btn = $("btn-save");
    btn.disabled = true;
    $("save-hint").textContent = "保存中…";
    try {
      state.config = await apiPost("/api/config", cfg);
      renderSettings();
      toast("设置已保存并生效", "ok");
      $("save-hint").textContent = "已保存";
    } catch (e) {
      showSettingsErrors([e.message]);
      toast("保存失败", "err");
      $("save-hint").textContent = "";
    } finally {
      btn.disabled = false;
      setTimeout(() => {
        $("save-hint").textContent = "";
      }, 3000);
    }
  });

  // 关闭 / 隐藏页面时停掉日志轮询，避免后台空转
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) stopTimers();
    else startTimers();
  });
}

function startTimers() {
  stopTimers();
  state.stateTimer = setInterval(refreshState, 2000);
  state.logTimer = setInterval(refreshLogs, 3000);
}

function stopTimers() {
  if (state.stateTimer) clearInterval(state.stateTimer);
  if (state.logTimer) clearInterval(state.logTimer);
  state.stateTimer = null;
  state.logTimer = null;
}

/* ---------------- 启动 ---------------- */

async function boot() {
  bindEvents();
  await refreshState();
  // 概览页的「受保护端口」明细需要配置，先取一次；
  // 失败不回退整个页面，只让明细行保持默认文案。
  try {
    state.config = await apiGet("/api/config");
    renderStatus();
  } catch (_) {
    /* 配置读取失败不影响概览其余部分 */
  }
  await refreshAdapters();
  try {
    const meta = await apiGet("/api/meta");
    $("log-path").textContent = "日志文件：" + meta.log_file;
  } catch (_) {
    /* 元信息缺失不影响主流程 */
  }
  startTimers();
}

boot();
