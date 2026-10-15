//! 命令行参数。
//!
//! 程序是无窗口形态（控制台 + 系统托盘），因此命令行只承担少量开关，
//! 全部配置都通过 Web 面板调整。

use std::path::PathBuf;

use portguard_core::error::{AppError, Result};

/// 程序名与版本，供帮助与单实例提示复用。
pub const NAME: &str = "PortGuard";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 解析后的选项。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// 服务模式：由计划任务以 SYSTEM 身份启动。
    ///
    /// 该模式运行在会话 0，没有交互桌面，因此既不创建托盘图标，也不自动打开浏览器。
    pub service: bool,
    /// 是否启用 Web 面板。
    pub panel: bool,
    /// 只把已在运行实例的面板打开，自身不作为守护进程驻留。
    pub open_only: bool,
    /// 自定义数据目录（便于调试与便携部署）。
    pub data_dir: Option<PathBuf>,
    /// 立即开始保护（默认开启，`--no-start` 可关闭以便只开面板）。
    pub auto_start: bool,
    /// 保留控制台窗口。
    ///
    /// 默认为 `false`：双击启动时把控制台窗口隐藏掉，任务栏只留托盘图标，
    /// 输出改由日志文件与控制面板承载。加 `--console` 或从 cmd 启动时
    /// 仍然保留窗口，便于排查启动期问题。
    pub console: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            service: false,
            panel: true,
            open_only: false,
            data_dir: None,
            auto_start: true,
            console: false,
        }
    }
}

/// 解析结果。
#[derive(Debug)]
pub enum Parsed {
    /// 正常启动。
    Run(Options),
    /// 只打印信息后退出。
    Print(String),
}

/// 帮助文本。
pub fn help_text() -> String {
    format!(
        "{name} {version} —— 恶意连接识别与自动封停\n\
         \n\
         用法：{name} [选项]\n\
         \n\
         选项：\n\
         \x20 --service          服务模式：由 Windows 服务管理器（SCM）拉起，不开浏览器、不建托盘\n\
         \x20 --console          保留控制台窗口（默认隐藏，只留托盘图标）\n\
         \x20 --no-panel         不启动 Web 控制面板\n\
         \x20 --no-start         启动后不自动开始保护\n\
         \x20 --open-panel       只打开已运行实例的面板后退出\n\
         \x20 --data-dir <路径>  指定数据目录（默认：程序目录下的 data）\n\
         \x20 -h, --help         显示本帮助\n\
         \x20 -V, --version      显示版本号\n\
         \n\
         启动后浏览器访问 http://127.0.0.1:58080 查看与控制。",
        name = NAME,
        version = VERSION
    )
}

/// 解析参数（不含程序自身路径）。
pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Parsed> {
    let mut opts = Options::default();
    let mut it = args.into_iter();

    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(Parsed::Print(help_text())),
            "-V" | "--version" => {
                return Ok(Parsed::Print(format!("{} {}", NAME, VERSION)));
            }
            // 服务模式下由 SCM 在开机时拉起，跑在会话 0 且无人盯着控制台，
            // 因此主程序会跳过「自动打开浏览器」这一步，并进入服务分发
            "--service" => opts.service = true,
            "--console" => opts.console = true,
            "--no-panel" => opts.panel = false,
            "--no-start" => opts.auto_start = false,
            "--open-panel" => opts.open_only = true,
            "--data-dir" => {
                let value = it.next().ok_or_else(|| {
                    AppError::Other("--data-dir 后必须跟一个目录路径".to_string())
                })?;
                if value.trim().is_empty() {
                    return Err(AppError::Other("--data-dir 不能为空".to_string()));
                }
                opts.data_dir = Some(PathBuf::from(value));
            }
            other => {
                return Err(AppError::Other(format!(
                    "无法识别的参数：{}\n\n{}",
                    other,
                    help_text()
                )));
            }
        }
    }
    Ok(Parsed::Run(opts))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(args: &[&str]) -> Options {
        let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        match parse(owned).unwrap() {
            Parsed::Run(o) => o,
            Parsed::Print(_) => panic!("不应是打印退出"),
        }
    }

    #[test]
    fn 默认选项符合预期() {
        let o = parse_ok(&[]);
        assert!(o.panel);
        assert!(o.auto_start);
        assert!(!o.service);
        assert!(!o.open_only);
        assert!(o.data_dir.is_none());
    }

    #[test]
    fn 开关参数逐个生效() {
        assert!(!parse_ok(&["--no-panel"]).panel);
        assert!(!parse_ok(&["--no-start"]).auto_start);
        assert!(parse_ok(&["--service"]).service);
        assert!(parse_ok(&["--open-panel"]).open_only);
        assert!(parse_ok(&["--console"]).console);
    }

    #[test]
    fn 默认隐藏控制台窗口() {
        assert!(!parse_ok(&[]).console, "默认应隐藏黑窗口，只留托盘图标");
        assert!(help_text().contains("--console"));
    }

    #[test]
    fn 数据目录支持带空格路径() {
        let o = parse_ok(&["--data-dir", "D:\\Port Guard\\数据"]);
        assert_eq!(o.data_dir.unwrap().to_string_lossy(), "D:\\Port Guard\\数据");
    }

    #[test]
    fn 缺失或空的数据目录报错() {
        assert!(parse(vec!["--data-dir".to_string()]).is_err());
        assert!(parse(vec!["--data-dir".to_string(), "  ".to_string()]).is_err());
    }

    #[test]
    fn 帮助与版本直接打印() {
        assert!(matches!(
            parse(vec!["--help".to_string()]).unwrap(),
            Parsed::Print(_)
        ));
        match parse(vec!["-V".to_string()]).unwrap() {
            Parsed::Print(text) => assert!(text.contains(VERSION)),
            _ => panic!("应打印版本"),
        }
    }

    #[test]
    fn 未知参数给出中文提示() {
        let err = parse(vec!["--nope".to_string()]).unwrap_err();
        assert!(err.to_string().contains("无法识别的参数"));
        assert!(err.to_string().contains("用法"));
    }
}
