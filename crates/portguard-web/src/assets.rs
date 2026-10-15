//! 内嵌的 Web 资源。
//!
//! 通过 `include_str!` 在编译期把前端资源写进 exe，运行时无需任何外部文件，
//! 从而实现「单文件部署」（等价于 Go 的 `embed`）。
//! 修改前端代码后必须重新编译才能生效——这是单文件形态的必然代价。

/// 一个内嵌资源。
pub struct Asset {
    /// 请求路径（不含查询串）。
    pub path: &'static str,
    /// MIME 类型。
    pub mime: &'static str,
    /// 内容。
    pub body: &'static str,
}

/// 全部内嵌资源。
pub const ASSETS: &[Asset] = &[
    Asset {
        path: "/assets/style.css",
        mime: "text/css; charset=utf-8",
        body: include_str!("../assets/style.css"),
    },
    Asset {
        path: "/assets/i18n.js",
        mime: "application/javascript; charset=utf-8",
        body: include_str!("../assets/i18n.js"),
    },
    Asset {
        path: "/assets/app.js",
        mime: "application/javascript; charset=utf-8",
        body: include_str!("../assets/app.js"),
    },
];

/// 首页。
pub const INDEX_HTML: &str = include_str!("../assets/index.html");

/// 按请求路径查找资源。
pub fn lookup(path: &str) -> Option<&'static Asset> {
    ASSETS.iter().find(|a| a.path == path)
}

/// 资源总字节数（启动日志里展示，便于确认版本）。
pub fn total_bytes() -> usize {
    ASSETS.iter().map(|a| a.body.len()).sum::<usize>() + INDEX_HTML.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 首页包含关键挂载点() {
        // 这些 id 是 app.js 的契约，改名必须同步改前端
        for id in [
            "id=\"tbody-connections\"",
            "id=\"tbody-bans\"",
            "id=\"quick-switches\"",
            "id=\"protect-rows\"",
            "id=\"logs\"",
            // 诊断区：没有这两个挂载点，面板就无法回答「包到底有没有被抓到」
            "id=\"ignore-stats\"",
            "id=\"parse-note\"",
            "id=\"tbody-observe\"",
            "id=\"cfg-count-accept\"",
            // 界面语言设置：设置页必须能改语言，且 app.js 要把它写回配置
            "id=\"cfg-language\"",
            // 版本信息已随导航移到顶部状态条，仍是 app.js 的写入目标
            "id=\"foot-version\"",
        ] {
            assert!(INDEX_HTML.contains(id), "首页缺少挂载点 {}", id);
        }
    }

    #[test]
    fn 导航位于顶部横排且无侧边栏() {
        // 布局契约：窄屏（笔记本）下左右空间必须全部留给数据表，
        // 因此导航只能横排在 .topbar 内，不允许再出现占宽的侧边栏容器
        assert!(INDEX_HTML.contains("class=\"topbar\""), "首页缺少顶部导航容器");
        assert!(!INDEX_HTML.contains("sidebar"), "导航应横排在顶部，不应存在侧边栏");
        let css = lookup("/assets/style.css").unwrap().body;
        assert!(!css.contains(".sidebar"), "样式表不应残留侧边栏规则");
        for page in ["overview", "connections", "bans", "settings", "logs"] {
            assert!(
                INDEX_HTML.contains(&format!("data-page=\"{}\"", page)),
                "顶部导航缺少 {} 入口",
                page
            );
        }
    }

    #[test]
    fn 数据表页撑满视口高度() {
        // 布局契约：当前连接 / 封停列表 / 运行日志三页的数据区必须靠 flex
        // 撑满顶栏以下的剩余高度，不允许再用 calc(100vh - 常量) 猜高度
        // （常量与实际顶栏不符时会出现「只显示几行 + 底部大片空白」）
        for page in ["connections", "bans", "logs"] {
            assert!(
                INDEX_HTML.contains(&format!("class=\"page fill\" id=\"page-{}\"", page)),
                "{} 页缺少 fill 类，无法撑满高度",
                page
            );
        }
        let css = lookup("/assets/style.css").unwrap().body;
        assert!(css.contains(".page.active.fill"), "样式表缺少 fill 页高度规则");
        assert!(css.contains(".page.fill > .card"), "样式表缺少 fill 页卡片伸缩规则");
        assert!(
            css.contains(".page.fill .table-wrap"),
            "样式表缺少 fill 页滚动区规则"
        );
        assert!(
            !css.contains("100vh - 320px"),
            "不应再用 calc(100vh - 常量) 固定表体高度"
        );
    }

    #[test]
    fn 设置页提供端口与名单备注挂载点() {
        // 名单备注网格是静态挂载点（三组端口的网格由脚本按分组拼 id 动态生成）
        for id in ["id=\"notes-whitelist\"", "id=\"notes-blacklist\""] {
            assert!(INDEX_HTML.contains(id), "首页缺少备注挂载点 {}", id);
        }
        let js = lookup("/assets/app.js").unwrap().body;
        assert!(js.contains("\"notes-\" + g.key"), "端口备注网格 id 必须跟随分组生成");
        assert!(js.contains("renderNoteGrid"), "脚本缺少备注网格渲染");
        assert!(js.contains("portNoteKeys"), "脚本缺少端口备注键解析");
        // 备注必须随整份配置写回：漏掉就会被后端按字段默认值清空（历史同类故障）
        assert!(js.contains("notes = pickNotes("), "collectSettings 必须写回备注字段");
        let css = lookup("/assets/style.css").unwrap().body;
        assert!(css.contains(".note-grid"), "样式表缺少备注网格规则");
        assert!(css.contains(".note-tag"), "样式表缺少数据表备注规则");
    }

    #[test]
    fn 界面语言资源内嵌且文案成对() {
        let js = lookup("/assets/i18n.js").expect("语言文案表必须内嵌").body;
        // 首页每个语言标记都必须在文案表里有中文与英文两份：
        // 漏一份的表现为「切到英文后这一块还是中文」，且在界面上看不出来是漏了
        let keys = i18n_keys(INDEX_HTML);
        assert!(keys.len() > 50, "首页语言标记过少：{}", keys.len());
        for key in &keys {
            let entry = i18n_entry(js, key)
                .unwrap_or_else(|| panic!("语言文案表缺少键 {}", key));
            assert!(entry.contains("zh:"), "键 {} 缺少中文文案：{}", key, entry);
            assert!(entry.contains("en:"), "键 {} 缺少英文文案：{}", key, entry);
        }

        // 脚本里出现的每个文案键（含 t() 的参数与数组里的键）都必须有译文，
        // 否则切到英文时那处会直接显示成键名
        let app = lookup("/assets/app.js").expect("app.js 必须内嵌").body;
        let app_keys = i18n_like_literals(app);
        // 扫描本身要有产出，否则下面的循环形同虚设（键全写死中文它也会「通过」）
        assert!(app_keys.len() > 40, "脚本里的文案键只有 {} 个，扫描逻辑或脚本异常", app_keys.len());
        for key in app_keys {
            let entry = i18n_entry(js, &key).unwrap_or_else(|| panic!("app.js 用了未定义的文案键 {}", key));
            assert!(entry.contains("zh:") && entry.contains("en:"), "键 {} 文案不成对：{}", key, entry);
        }

        // 脚本必须真的把文案表与应用逻辑接起来
        assert!(app.contains("PG_I18N"), "脚本应从 i18n.js 取文案");
        assert!(app.contains("[data-i18n]"), "脚本应刷新静态节点的文案");
        // 语言必须随整份配置写回：漏掉会被后端按字段默认值当成 auto（与备注同类故障）
        assert!(
            app.contains("base.panel.language = $(\"cfg-language\").value"),
            "collectSettings 必须写回界面语言字段"
        );
        assert!(
            INDEX_HTML.contains("/assets/i18n.js"),
            "首页必须先加载语言文案表"
        );
        // 切换语言只准刷新文案，不准重建设置页表单 —— 重建会把用户还没保存的
        // 端口 / 名单 / 备注输入冲掉（与「改一处丢一处」的历史故障同类）
        assert!(
            app.contains("retranslateSettings()"),
            "切换语言必须走只改文案的路径，而非重建整张表单"
        );
        assert!(
            app.contains("function retranslateSettings"),
            "脚本缺少设置页文案的原地刷新实现"
        );
    }

    /// 首页上的全部语言键（data-i18n / data-i18n-ph / data-i18n-title）。
    fn i18n_keys(html: &str) -> Vec<String> {
        let mut keys = Vec::new();
        for attr in ["data-i18n=\"", "data-i18n-ph=\"", "data-i18n-title=\""] {
            let mut rest = html;
            while let Some(i) = rest.find(attr) {
                let tail = &rest[i + attr.len()..];
                if let Some(end) = tail.find('"') {
                    let key = tail[..end].to_string();
                    if !keys.contains(&key) {
                        keys.push(key);
                    }
                }
                rest = &tail[tail.find('"').map(|e| e + 1).unwrap_or(tail.len())..];
            }
        }
        keys
    }

    /// 扫描脚本里「长得像文案键」的字符串字面量：至少两段、每段都是
    /// 小写字母打头的小写字母 / 数字 / 下划线，段间用点连接。
    ///
    /// 只在源码里做静态扫描，因此像 `"reason." + x` 这种拼接出来的键不会被算进来
    /// （拼接的键只能靠 i18n.js 自身保证成对）。
    fn i18n_like_literals(js: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut rest = js;
        while let Some(i) = rest.find('"') {
            let tail = &rest[i + 1..];
            let end = match tail.find('"') {
                Some(e) => e,
                None => break,
            };
            let lit = &tail[..end];
            if is_i18n_key(lit) && !out.iter().any(|k| k == lit) {
                out.push(lit.to_string());
            }
            rest = &tail[end + 1..];
        }
        out
    }

    fn is_i18n_key(s: &str) -> bool {
        let parts: Vec<&str> = s.split('.').collect();
        parts.len() >= 2
            && parts.iter().all(|p| {
                p.chars().next().map(|c| c.is_ascii_lowercase()).unwrap_or(false)
                    && p.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            })
    }

    /// 取文案表里某个键的整条记录（`"键": { zh: …, en: … },`）。
    fn i18n_entry<'a>(js: &'a str, key: &str) -> Option<&'a str> {
        let needle = format!("\"{}\": {{", key);
        let start = js.find(&needle)?;
        let rest = &js[start..];
        let end = rest.find("},").unwrap_or(rest.len());
        Some(&rest[..end])
    }

    #[test]
    fn 资源可按键路径查到() {
        let css = lookup("/assets/style.css").unwrap();
        assert!(css.mime.starts_with("text/css"));
        let js = lookup("/assets/app.js").unwrap();
        assert!(js.mime.starts_with("application/javascript"));
        assert!(lookup("/assets/missing.js").is_none());
        assert!(lookup("/").is_none(), "首页走单独分支，不在资源表内");
    }

    #[test]
    fn 脚本不使用危险的内联写入() {
        // 数据一律走 textContent；innerHTML 只允许出现在 el() 的注释与关键字分支里
        let js = lookup("/assets/app.js").unwrap().body;
        assert!(
            !js.contains("innerHTML = ") || js.matches("innerHTML").count() <= 3,
            "前端不应大量使用 innerHTML 拼接数据（XSS 风险）"
        );
        assert!(js.contains("textContent"), "前端应通过 textContent 写入数据");
    }

    #[test]
    fn 资源体积可控() {
        // 单文件部署下资源体积直接进 exe，设一个宽松上限防止误提交大文件
        assert!(total_bytes() < 512 * 1024, "内嵌资源体积异常：{}", total_bytes());
    }
}
