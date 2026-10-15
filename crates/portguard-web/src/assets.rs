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
