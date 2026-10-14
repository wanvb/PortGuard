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
        ] {
            assert!(INDEX_HTML.contains(id), "首页缺少挂载点 {}", id);
        }
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
