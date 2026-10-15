/* ============================================================
   PortGuard 控制面板前端逻辑
   纯 ES6 + fetch，无框架、无构建步骤。

   安全约定：所有来自接口的数据一律用 textContent 写入 DOM，
   绝不用 innerHTML 拼接，避免把日志/客户端名里的内容当作 HTML 执行。

   界面语言：文案表在 i18n.js，本文件所有面向用户的文字都经 t() 取，
   不得再写死中文——写死的那一份永远不会跟着语言设置切换。
   ============================================================ */

"use strict";

/* ---------------- 界面语言（中文 / 英文） ----------------
   静态节点走 index.html 上的 data-i18n / data-i18n-ph / data-i18n-title，
   动态内容在渲染时调 t()。实际生效的语言来自配置 panel.language：
   auto 时用服务器系统语言（后端 /api/meta 下发），设置页里改了下拉框但还没
   保存时先按这个未保存的选择预览。 */

/** 当前生效的语言（"zh" / "en"）。 */
let LANG = "zh";

/** 取当前语言的文案；缺键退回中文，再退回键名本身（宁可露出键名也不错位）。 */
function t(key, params) {
  const entry = (window.PG_I18N || {})[key];
  let text = entry ? entry[LANG] || entry.zh || key : key;
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      text = text.split("{" + k + "}").join(String(v));
    }
  }
  return text;
}

/** 把静态节点的文案刷成当前语言。 */
function applyI18n() {
  for (const node of document.querySelectorAll("[data-i18n]")) {
    node.textContent = t(node.getAttribute("data-i18n"));
  }
  for (const node of document.querySelectorAll("[data-i18n-ph]")) {
    node.setAttribute("placeholder", t(node.getAttribute("data-i18n-ph")));
  }
  for (const node of document.querySelectorAll("[data-i18n-title]")) {
    node.setAttribute("title", t(node.getAttribute("data-i18n-title")));
  }
  document.documentElement.lang = LANG === "en" ? "en" : "zh-CN";
  document.title = t("app.title");
}

/** 语言设置（auto / zh / en）→ 实际生效的语言。 */
function resolveLanguage(setting) {
  if (setting === "zh" || setting === "en") return setting;
  // auto：用服务器系统语言的探测结果（后端下发），取不到按中文
  const detected = state.meta && state.meta.language;
  return detected === "en" ? "en" : "zh";
}

/** 当前应生效的语言：设置页里未保存的下拉框选择优先于磁盘上的配置。 */
function effectiveLanguage() {
  const setting =
    state.langPreview || (state.config && state.config.panel && state.config.panel.language) || "auto";
  return resolveLanguage(setting);
}

/** 切换语言：刷新静态文案，并重渲染当前页面里由脚本生成的内容。 */
function applyLanguage() {
  LANG = effectiveLanguage();
  applyI18n();
  if (state.status) {
    renderStatus();
    renderQuickSwitches();
    renderEvents();
    renderConnections();
    renderBans();
  }
  // 设置页只刷新脚本生成的文案，不重建表单（重建会冲掉用户还没保存的输入）
  if (state.page === "settings" && state.config) retranslateSettings();
  if (state.page === "logs") renderLogs();
  renderLogPath();
}

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

/** 后端下发的方向文案（中文枚举）→ 当前语言；认不出的值原样展示。 */
function directionText(value) {
  if (value === "入站") return t("dir.in");
  if (value === "出站") return t("dir.out");
  return value;
}

/** TCP 标志类别文本同理：只有「其它」是中文枚举，其余是 SYN / ACK 等原样展示。 */
function flagsText(value) {
  return value === "其它" ? t("flags.other") : value;
}

/** 秒 → 人类可读时长。 */
function fmtDuration(seconds) {
  if (seconds === null || seconds === undefined) return t("misc.permanent");
  let s = Math.max(0, Math.floor(seconds));
  const d = Math.floor(s / 86400);
  s %= 86400;
  const h = Math.floor(s / 3600);
  s %= 3600;
  const m = Math.floor(s / 60);
  s %= 60;
  if (d > 0) return t("dur.days", { d, h });
  if (h > 0) return t("dur.hours", { h, m });
  if (m > 0) return t("dur.minutes", { m, s });
  return t("dur.seconds", { s });
}

function fmtNumber(n) {
  return (n === null || n === undefined ? 0 : n).toLocaleString(LANG === "en" ? "en-US" : "zh-CN");
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
    $("modal-ok").textContent = okLabel || t("modal.confirm");
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

/** 把服务端返回的错误体转成提示（服务端文案本身是中文，原样展示）。 */
function describeHttpError(status, text) {
  try {
    const body = JSON.parse(text);
    if (body && body.error) return body.error;
  } catch (_) {
    /* 非 JSON 响应，退回到原始文本 */
  }
  return text
    ? t("err.request", { status, text })
    : t("err.request_short", { status });
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
  /** `/api/meta` 下发：语言设置为 auto 时用它决定界面语言。 */
  meta: null,
  /** 设置页里改了下拉框但还没保存的语言（保存或重载后清空）。 */
  langPreview: null,
  page: "overview",
  stateTimer: null,
  logTimer: null,
};

const QUICK_SWITCHES = [
  { key: "risky_ports", field: "risky_ports", title: "sw.risky", hint: "sw.risky_hint" },
  { key: "block_icmp", field: "block_icmp", title: "sw.icmp", hint: "sw.icmp_hint" },
  { key: "autostart", field: "autostart", title: "sw.autostart", hint: "sw.autostart_hint" },
  { key: "rdp_guard", field: "rdp_enabled", title: "sw.rdp", hint: "sw.rdp_hint" },
];

/* ---------------- 渲染：顶部状态 ---------------- */

function renderStatus() {
  const s = state.status;
  if (!s) return;

  const runDot = $("chip-run-dot");
  runDot.className = "dot " + (s.running ? "on" : "off");
  $("chip-run").textContent = s.running ? t("top.running") : t("top.stopped");

  $("chip-adapter").textContent = s.adapter || t("top.adapter_none");
  $("chip-ip").textContent = s.local_ip || "-";

  const adminDot = $("chip-admin-dot");
  adminDot.className = "dot " + (s.admin ? "on" : "warn");
  $("chip-admin").textContent = s.admin ? t("top.admin") : t("top.no_admin");

  $("chip-uptime").textContent = fmtDuration(s.stats.uptime_seconds);

  $("stat-tracking").textContent = fmtNumber(s.stats.tracking);
  $("stat-banned").textContent = fmtNumber(s.stats.banned);
  $("stat-banned-foot").textContent = t("ov.banned_foot", { n: fmtNumber(s.stats.permanent) });
  $("stat-ports").textContent = fmtNumber(s.protected_ports);
  $("stat-ports-foot").textContent = protectedPortsText(s);
  $("stat-packets").textContent = fmtNumber(s.stats.captured_packets);
  $("stat-packets-foot").textContent = t("ov.packets_foot", { n: fmtNumber(s.stats.total_bans) });
  renderIgnoreStats(s);
  renderParseNote(s);
  renderObserve(s);

  $("foot-version").textContent = `PortGuard v${s.version}`;
  $("badge-connections").textContent = state.connections.length;
  $("badge-bans").textContent = state.bans.length;

  $("btn-start").disabled = s.running;
  $("btn-stop").disabled = !s.running;

  // 地理位置库状态：加载成功给出路径，否则给出原因与放置位置（原因由后端给，中文）
  const geoTip = $("geo-status");
  if (geoTip) {
    const text = s.geo_status || "";
    geoTip.textContent = s.geo_ready ? t("set.geo_loaded", { path: text }) : text;
    geoTip.className = s.geo_ready ? "muted" : "muted warn";
  }

  // 权限不足时给出明确后果提示，而不是等到封停失败
  if (!s.admin && !state.adminWarned) {
    state.adminWarned = true;
    toast(t("toast.need_admin"), "warn");
  }
}

/** 受保护端口明细：把三组端口直接写进卡片脚注，避免只看到一个总数。
 *
 *  配置尚未取到时退回固定文案（概览页首屏）。 */
function protectedPortsText(s) {
  const protect = state.config && state.config.protect;
  if (!protect) return t("ov.ports_foot_default");
  const fmt = (g) => {
    const rule = protect[g] || {};
    const ports = rule.ports || [];
    if (!ports.length) return t("ov.ports_none");
    // 带上备注，让「这个端口是谁在用的」在概览页就能看到
    const notes = rule.notes || {};
    return ports
      .map((p) => (notes[String(p)] ? `${p}(${notes[String(p)]})` : String(p)))
      .join(",");
  };
  if (!s.protected_ports) return t("ov.ports_all_empty");
  return `TCP ${fmt("tcp")} · WEB ${fmt("http")} · UDP ${fmt("udp")}`;
}

/** 判定明细：抓包数在涨但连接列表空着时，用这几项区分问题出在哪一层。 */
function renderIgnoreStats(s) {
  const box = $("ignore-stats");
  if (!box || !s.stats) return;
  const ig = s.stats.ignored || {};
  const items = [
    { label: "ov.ig_not_local", value: ig.not_local, hint: "ov.ig_not_local_hint" },
    { label: "ov.ig_outbound", value: ig.outbound, hint: "ov.ig_outbound_hint" },
    { label: "ov.ig_not_new", value: ig.not_new_connection, hint: "ov.ig_not_new_hint" },
    { label: "ov.ig_port_unprotected", value: ig.port_not_protected, hint: "ov.ig_port_unprotected_hint" },
    { label: "ov.ig_icmp", value: ig.icmp, hint: "ov.ig_icmp_hint" },
  ];
  box.textContent = "";
  for (const it of items) {
    box.appendChild(
      el("div", { class: "stat" }, [
        el("div", { class: "stat-label", text: t(it.label) }),
        el("div", { class: "stat-value", text: fmtNumber(it.value || 0) }),
        el("div", { class: "stat-foot", text: t(it.hint) }),
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
  // 样本说明由抓包层生成（中文），原样附在后面，不做翻译
  let text = errs ? t("ov.parse_some", { n: fmtNumber(errs) }) : t("ov.parse_zero");
  if (s.count_accept) {
    text += t("ov.parse_count_accept");
  }
  if (samples.length) {
    text += t("ov.parse_samples", { s: samples.join(" | ") });
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
            el("strong", { text: s.running ? t("ov.obs_empty_running") : t("ov.obs_empty_stopped") }),
            el("span", {
              text: s.running ? t("ov.obs_empty_running_hint") : t("ov.obs_empty_stopped_hint"),
            }),
          ]),
        ]),
      ])
    );
    return;
  }
  for (const o of rows) {
    const row = el("tr");
    row.appendChild(
      el("td", {}, [el("span", { class: "badge group", text: directionText(o.direction) })])
    );
    row.appendChild(el("td", { class: "mono", text: o.protocol }));
    row.appendChild(el("td", { class: "mono", text: String(o.port) }));
    row.appendChild(el("td", { class: "mono", text: flagsText(o.flags) }));
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
          t(enabled ? "toast.switched_on" : "toast.switched_off", { name: t(item.title) })
        );
        ev.target.disabled = false;
      },
    });
    input.checked = on;
    box.appendChild(
      el("label", { class: "switch" }, [
        input,
        el("span", { class: "switch-text" }, [
          el("b", { text: t(item.title) }),
          el("span", { text: t(item.hint) }),
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
        el("strong", { text: t("ov.events_empty") }),
        el("span", { text: t("ov.events_empty_hint") }),
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

/** 备注内联展示：没有备注时返回 null，调用方直接跳过（不占位）。 */
function noteTag(text) {
  return text ? el("span", { class: "muted note-tag", text: text }) : null;
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
            el("strong", { text: keyword ? t("conn.no_match") : t("conn.empty") }),
            el("span", {
              text: keyword ? t("conn.no_match_hint") : t("conn.empty_hint"),
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
    row.appendChild(el("td", { class: "mono" }, [c.ip, noteTag(c.ip_note)]));
    row.appendChild(el("td", { class: "muted", text: c.location || t("misc.unknown") }));
    row.appendChild(el("td", {}, [el("span", { class: "badge group", text: c.group })]));
    row.appendChild(el("td", { class: "mono" }, [String(c.service_port), noteTag(c.port_note)]));
    row.appendChild(
      el("td", {
        title: t("conn.meter_title", { count: c.count, threshold: c.threshold }),
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
                text: t("btn.unban"),
                onclick: () => unban(c.ip),
              })
            : el("button", {
                class: "btn sm danger",
                text: t("btn.ban"),
                onclick: () => banIp(c.ip, true),
              }),
          el("button", {
            class: "btn sm",
            text: t("btn.whitelist"),
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
    return el("span", { class: "badge whitelist", text: t("badge.whitelist") });
  }
  if (c.state === "PERMANENT") {
    return el("span", { class: "badge permanent", text: t("badge.permanent") });
  }
  if (c.state === "BANNED") return el("span", { class: "badge banned", text: t("badge.banned") });
  return el("span", { class: "badge tracking", text: t("badge.tracking") });
}

/* ---------------- 渲染：封停表 ---------------- */

/** 封停原因：优先按后端下发的稳定标识（blacklist / tcp_threshold / …）取当前语言文案，
 *  标识认不出时退回后端给的中文文案，绝不显示成空单元格。 */
function reasonText(b) {
  const key = "reason." + (b.reason || "");
  if ((window.PG_I18N || {})[key]) return t(key);
  return b.reason_label || b.reason || "";
}

function renderBans() {
  const body = $("tbody-bans");
  body.textContent = "";
  if (!state.bans.length) {
    body.appendChild(
      el("tr", {}, [
        el("td", { colspan: "10" }, [
          el("div", { class: "empty" }, [
            el("strong", { text: t("bans.empty") }),
            el("span", { text: t("bans.empty_hint") }),
          ]),
        ]),
      ])
    );
    return;
  }

  for (const b of state.bans) {
    const row = el("tr", { class: "banned" });
    row.appendChild(el("td", { class: "mono" }, [b.ip, noteTag(b.ip_note)]));
    row.appendChild(el("td", { class: "muted", text: b.location || t("misc.unknown") }));
    row.appendChild(el("td", { text: reasonText(b) }));
    row.appendChild(el("td", { class: "mono", text: b.protocol || "-" }));
    row.appendChild(
      el("td", { class: "mono" }, [
        b.service_port ? String(b.service_port) : "-",
        noteTag(b.port_note),
      ])
    );
    row.appendChild(el("td", { class: "mono", text: fmtNumber(b.attempt_count) }));
    row.appendChild(el("td", { class: "mono muted", text: fmtTime(b.created_at_ms) }));
    row.appendChild(
      el("td", {
        class: "mono",
        text: b.permanent ? t("misc.permanent") : fmtDuration(b.remaining_seconds),
      })
    );
    row.appendChild(el("td", { class: "mono muted", text: b.rule_name }));
    row.appendChild(
      el("td", {}, [
        el("div", { class: "form-actions" }, [
          el("button", { class: "btn sm", text: t("btn.unban"), onclick: () => unban(b.ip) }),
          el("button", {
            class: "btn sm",
            text: t("btn.whitelist"),
            onclick: () => whitelistAdd(b.ip),
          }),
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
    box.appendChild(el("div", { class: "muted", text: t("log.empty") }));
  }
  if ($("log-autoscroll").checked) box.scrollTop = box.scrollHeight;
}

/* ---------------- 渲染：设置 ---------------- */

// max_attempts 是配置里缺该分组时的兜底值，必须与后面 `ProtectConfig::default` 一致：
// TCP-WEB 阈值远高于普通 TCP，一次页面访问要连带 CSS / JS / 图片等数十个连接，
// 阈值过低会把正常访客秒封。
const PROTECT_GROUPS = [
  { key: "tcp", name: "g.tcp", hint: "g.tcp_hint", max_attempts: 5 },
  { key: "http", name: "g.http", hint: "g.http_hint", max_attempts: 300 },
  { key: "udp", name: "g.udp", hint: "g.udp_hint", max_attempts: 5 },
];

/* ---------------- 备注编辑（纯展示字段，不参与判定） ----------------
   端口与名单规则的下方各有一张备注网格：一行一个键 + 一个备注输入框。
   网格按输入框里当前的端口 / 规则实时重建，因此备注缓存在客户端：
   重建时从缓存取值，用户正在输入的内容不会被冲掉。 */

let noteCache = {}; // `${范围}:${键}` → 备注

const noteKey = (scope, key) => scope + ":" + key;

/** 记下用户正在输入的备注（尚未保存，但网格重建后要能还原）。 */
function cacheNote(scope, key, value) {
  if (value) noteCache[noteKey(scope, key)] = value;
  else delete noteCache[noteKey(scope, key)];
}

/** 从服务端配置装载某个范围的备注（每次重渲染设置页时整体重建缓存）。 */
function loadNotes(scope, map) {
  for (const [k, v] of Object.entries(map || {})) cacheNote(scope, k, v);
}

/** 按当前键取出要提交的备注表；缓存里的其余条目（已删掉的键）一律不带。 */
function pickNotes(scope, keys) {
  const out = {};
  for (const k of keys) {
    const v = (noteCache[noteKey(scope, k)] || "").trim();
    if (v) out[k] = v;
  }
  return out;
}

/** 去重且保持先后顺序。 */
function uniqueKeys(list) {
  return [...new Set(list)];
}

/** 端口输入框里当前合法的端口（输入过程中非法内容静默跳过，不在这里报错）。 */
function portNoteKeys(group) {
  const input = document.querySelector(`[data-group="${group}"][data-field="ports"]`);
  const ports = (input.value || "")
    .split(/[,，\s]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .map((s) => Number(s))
    .filter((n) => Number.isInteger(n) && n >= 1 && n <= 65535)
    .map((n) => String(n));
  return uniqueKeys(ports);
}

/** 名单输入框里当前的规则（键就是规则原文，与后端一致）。 */
function ruleNoteKeys(id) {
  return uniqueKeys(splitLines($(id).value));
}

/** 渲染一张备注网格：一行一个键 + 一个备注框。 */
function renderNoteGrid(box, scope, keys) {
  box.textContent = "";
  if (!keys.length) {
    box.appendChild(
      el("div", { class: "muted note-empty", text: t("note.empty") })
    );
    return;
  }
  for (const key of keys) {
    const input = el("input", {
      type: "text",
      class: "note-input",
      maxlength: "64",
      value: noteCache[noteKey(scope, key)] || "",
      placeholder: t("note.placeholder"),
    });
    input.addEventListener("input", () => cacheNote(scope, key, input.value.trim()));
    box.appendChild(
      el("div", { class: "note-row" }, [
        el("span", { class: "note-key", text: key }),
        input,
      ])
    );
  }
}

function renderSettings() {
  const cfg = state.config;
  if (!cfg) return;

  // 备注缓存以服务端配置为准整体重建（保存后 / 进入设置页时各一次）
  noteCache = {};
  loadNotes("lists", cfg.lists.notes);

  // 语言下拉框显示「未保存的预览值」，没有预览时才回落到磁盘上的配置
  $("cfg-language").value = state.langPreview || cfg.panel.language;
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
    const rule = cfg.protect[g.key] || { ports: [], max_attempts: g.max_attempts };
    loadNotes(g.key, rule.notes);

    const grid = el("div", { class: "note-grid", id: "notes-" + g.key });
    const ports = el("input", {
      type: "text",
      value: (rule.ports || []).join(","),
      placeholder: t("set.ports_ph"),
      "data-group": g.key,
      "data-field": "ports",
      title: t(g.hint),
    });
    // 端口一改就重建备注网格；只重建网格容器，输入框本身不重渲染，焦点不丢
    ports.addEventListener("input", () => renderNoteGrid(grid, g.key, portNoteKeys(g.key)));

    box.appendChild(
      el("div", { class: "port-row" }, [
        el("span", { class: "port-name", text: t(g.name) }),
        ports,
        el("span", { class: "muted", text: t("set.accumulated") }),
        el("input", {
          type: "number",
          min: "1",
          value: rule.max_attempts,
          "data-group": g.key,
          "data-field": "max_attempts",
          title: t("set.attempts_title"),
        }),
        el("span", { class: "muted", text: t("set.then_ban") }),
        grid,
      ])
    );
    renderNoteGrid(grid, g.key, portNoteKeys(g.key));
  }

  // 名单规则的备注网格（键是规则原文，黑白名单共用一张备注表）
  renderNoteGrid($("notes-whitelist"), "lists", ruleNoteKeys("cfg-whitelist"));
  renderNoteGrid($("notes-blacklist"), "lists", ruleNoteKeys("cfg-blacklist"));

  // 系统开关（与概览里的快捷开关等价，这里随配置一起保存）
  const sw = $("system-switches");
  sw.textContent = "";
  const sysItems = [
    { field: "risky_ports", title: "sw.risky", hint: "sw.risky_hint" },
    { field: "block_icmp", title: "sw.icmp", hint: "sw.icmp_hint" },
    { field: "autostart", title: "sw.autostart", hint: "sw.autostart_hint_settings" },
  ];
  for (const item of sysItems) {
    const input = el("input", { type: "checkbox", "data-system": item.field });
    input.checked = !!cfg.system[item.field];
    sw.appendChild(
      el("label", { class: "switch" }, [
        input,
        el("span", { class: "switch-text" }, [
          el("b", { text: t(item.title) }),
          el("span", { text: t(item.hint) }),
        ]),
      ])
    );
  }

  renderAdapterOptions();
}

/** 语言切换后只刷新设置页里由脚本生成的文案。
 *
 *  不能在这里直接 renderSettings()：那是从 state.config 重建整张表单，
 *  会把用户正在编辑、还没保存的内容（端口、名单、备注输入框里的字）全部冲掉，
 *  与历史上「改一处设置丢了另一处」的故障同类。 */
function retranslateSettings() {
  if (!$("notes-whitelist") || !$("system-switches")) return;

  PROTECT_GROUPS.forEach((g, i) => {
    const row = $("protect-rows").querySelectorAll(".port-row")[i];
    if (!row) return;
    const name = row.querySelector(".port-name");
    if (name) name.textContent = t(g.name);
    // 两个 .muted 依次是「累计连接」「次即封停」（网格里的空态占位排在其后）
    const muted = row.querySelectorAll(".muted");
    if (muted[0]) muted[0].textContent = t("set.accumulated");
    if (muted[1]) muted[1].textContent = t("set.then_ban");
    const ports = row.querySelector('[data-field="ports"]');
    if (ports) {
      ports.placeholder = t("set.ports_ph");
      ports.title = t(g.hint);
    }
    const attempts = row.querySelector('[data-field="max_attempts"]');
    if (attempts) attempts.title = t("set.attempts_title");
    const grid = row.querySelector(".note-grid");
    if (grid) renderNoteGrid(grid, g.key, portNoteKeys(g.key));
  });

  renderNoteGrid($("notes-whitelist"), "lists", ruleNoteKeys("cfg-whitelist"));
  renderNoteGrid($("notes-blacklist"), "lists", ruleNoteKeys("cfg-blacklist"));

  const sysKeys = {
    risky_ports: ["sw.risky", "sw.risky_hint"],
    block_icmp: ["sw.icmp", "sw.icmp_hint"],
    autostart: ["sw.autostart", "sw.autostart_hint_settings"],
  };
  for (const input of $("system-switches").querySelectorAll("[data-system]")) {
    const item = sysKeys[input.getAttribute("data-system")];
    if (!item) continue;
    const label = input.parentElement;
    const title = label.querySelector(".switch-text > b");
    const hint = label.querySelector(".switch-text > span");
    if (title) title.textContent = t(item[0]);
    if (hint) hint.textContent = t(item[1]);
  }

  // 网卡下拉框只能整体重建，先把「已选但未保存」的选择记下来再复原
  const select = $("cfg-adapter");
  const picked = select.value;
  renderAdapterOptions();
  if (picked && select.querySelector(`option[value="${picked}"]`)) select.value = picked;
}

function renderAdapterOptions() {
  const select = $("cfg-adapter");
  const current = (state.config && state.config.network.adapter) || "";
  select.textContent = "";

  const usable = state.adapters.filter((a) => a.usable);
  if (!usable.length) {
    select.appendChild(
      el("option", {
        value: "",
        text: state.adapters.length ? t("set.adapter_none") : t("set.adapter_loading"),
      })
    );
  }
  for (const a of usable) {
    const label = `${a.ip}${a.is_virtual ? t("set.adapter_virtual") : ""} · ${a.description}`;
    select.appendChild(el("option", { value: a.ip, text: label }));
  }
  select.value = current;
  if (select.value !== current && current) {
    // 配置里的网卡当前不在列表中（已拔网线等），保留为可选项以免保存时被清空
    select.appendChild(
      el("option", { value: current, text: `${current}${t("set.adapter_missing")}` })
    );
    select.value = current;
  }
}

/** 从表单收集配置对象（保留未在界面上暴露的字段）。 */
function collectSettings() {
  const base = JSON.parse(JSON.stringify(state.config));
  base.panel.bind = $("cfg-bind").value.trim();
  // 界面语言必须写回：整份配置提交时缺了它会被后端按字段默认值当成 auto
  base.panel.language = $("cfg-language").value;
  base.ban.duration_seconds = Number($("cfg-ban-duration").value) || 0;
  base.ban.permanent = $("cfg-ban-permanent").checked;
  base.lists.whitelist = splitLines($("cfg-whitelist").value);
  base.lists.blacklist = splitLines($("cfg-blacklist").value);
  // 备注必须写回：整份配置提交时缺了它会被后端按字段默认值当成空表，把用户备注清掉
  base.lists.notes = pickNotes("lists", ruleNoteKeys("cfg-whitelist").concat(ruleNoteKeys("cfg-blacklist")));
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
    // 只提交当前端口上的备注，已删掉的端口不带备注（后端也会再清一次）
    base.protect[g.key].notes = pickNotes(g.key, (base.protect[g.key].ports || []).map(String));
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
      return { ports: null, error: t("err.port_invalid", { port: p }) };
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
      el("b", { text: t("err.save_title") }),
      el("ul", {}, list.map((text) => el("li", { text }))),
    ])
  );
}

/* ---------------- 动作 ---------------- */

async function banIp(ip, permanent) {
  const ok = await confirmDialog(
    t("modal.ban_title"),
    t("modal.ban_text", { ip }),
    t("modal.ban_ok")
  );
  if (!ok) return;
  await run(() => apiPost("/api/ban", { ip, permanent }), t("toast.banned", { ip }));
}

async function unban(ip) {
  const ok = await confirmDialog(
    t("modal.unban_title"),
    t("modal.unban_text", { ip }),
    t("modal.unban_ok")
  );
  if (!ok) return;
  await run(() => apiPost("/api/unban", { ip }), t("toast.unbanned", { ip }));
}

async function whitelistAdd(ip) {
  const ok = await confirmDialog(
    t("modal.whitelist_title"),
    t("modal.whitelist_text", { ip }),
    t("modal.whitelist_ok")
  );
  if (!ok) return;
  await run(
    () => apiPost("/api/lists/add", { kind: "whitelist", rule: ip }),
    t("toast.whitelisted", { ip })
  );
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
    toast(t("toast.adapter_failed", { msg: e.message }), "err");
  }
}

/** 取面板元信息：语言设置为 auto 时靠它决定界面语言，同时拿日志文件路径。 */
async function refreshMeta() {
  try {
    state.meta = await apiGet("/api/meta");
    renderLogPath();
  } catch (_) {
    /* 元信息缺失不影响主流程，语言退回中文 */
  }
}

/** 日志文件路径（带语言前缀），元信息没取到时留空。 */
function renderLogPath() {
  if (state.meta) $("log-path").textContent = t("log.path", { path: state.meta.log_file });
}

async function loadSettings() {
  try {
    showSettingsErrors(null);
    state.config = await apiGet("/api/config");
    // 进设置页 / 放弃修改都从磁盘重来：未保存的语言预览作废
    state.langPreview = null;
    LANG = effectiveLanguage();
    applyI18n();
    await refreshAdapters();
    renderSettings();
  } catch (e) {
    showSettingsErrors([t("err.load_config", { msg: e.message })]);
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
    run(() => apiPost("/api/start"), t("toast.started"))
  );
  $("btn-stop").addEventListener("click", async () => {
    const ok = await confirmDialog(t("modal.stop_title"), t("modal.stop_text"), t("modal.stop_ok"));
    if (ok) await run(() => apiPost("/api/stop"), t("toast.stopped"));
  });

  $("btn-manual-ban").addEventListener("click", async () => {
    const ip = $("manual-ip").value.trim();
    if (!ip) {
      toast(t("bans.need_ip"), "warn");
      return;
    }
    await banIp(ip, $("manual-permanent").checked);
    $("manual-ip").value = "";
  });

  $("filter-connections").addEventListener("input", renderConnections);
  $("log-filter").addEventListener("change", renderLogs);

  // 语言下拉框：改了就立即按这个还没保存的选择预览，保存后才写进配置
  $("cfg-language").addEventListener("change", () => {
    state.langPreview = $("cfg-language").value;
    applyLanguage();
  });

  // 名单一改就重建该名单的备注网格（端口输入框是动态创建的，监听在渲染时挂）
  $("cfg-whitelist").addEventListener("input", () =>
    renderNoteGrid($("notes-whitelist"), "lists", ruleNoteKeys("cfg-whitelist"))
  );
  $("cfg-blacklist").addEventListener("input", () =>
    renderNoteGrid($("notes-blacklist"), "lists", ruleNoteKeys("cfg-blacklist"))
  );

  $("btn-adapters-refresh").addEventListener("click", refreshAdapters);
  $("btn-reload").addEventListener("click", () => {
    loadSettings();
    toast(t("toast.reloaded"), "ok");
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
      toast(t("toast.fix_errors"), "err");
      return;
    }

    const cfg = collectSettings();
    const btn = $("btn-save");
    btn.disabled = true;
    $("save-hint").textContent = t("set.saving");
    try {
      state.config = await apiPost("/api/config", cfg);
      // 语言可能刚改过：预览作废，按新配置（auto 时再取一次服务器语言）重解析
      state.langPreview = null;
      await refreshMeta();
      LANG = effectiveLanguage();
      applyI18n();
      renderSettings();
      toast(t("toast.saved"), "ok");
      $("save-hint").textContent = t("set.saved");
    } catch (e) {
      showSettingsErrors([e.message]);
      toast(t("toast.save_failed"), "err");
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
  // 元信息先取：语言设置为 auto 时界面语言由它决定，必须在首次渲染前拿到，
  // 否则英文环境会先闪一下中文
  await refreshMeta();
  LANG = effectiveLanguage();
  applyI18n();
  await refreshState();
  // 概览页的「受保护端口」明细需要配置，先取一次；
  // 失败不回退整个页面，只让明细行保持默认文案。
  try {
    state.config = await apiGet("/api/config");
    // 配置到手后语言才有准（auto 的判定依赖 meta，这里只需重刷一次文案）
    LANG = effectiveLanguage();
    applyI18n();
    renderStatus();
  } catch (_) {
    /* 配置读取失败不影响概览其余部分 */
  }
  await refreshAdapters();
  renderLogPath();
  startTimers();
}

boot();
