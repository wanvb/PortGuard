//! 配置文件读写：首次运行生成带注释的模板，损坏时备份而非静默覆盖。
//!
//! 规范 14 要求配置可读可改；规范 26.1 要求失败必须暴露而非假装成功。
//! 因此配置损坏时**不直接覆盖**——先备份为 `config.toml.broken-<时间戳>`，
//! 再用默认值启动，并把这次恢复动作如实上报给调用方。

use portguard_core::config::Config;
use portguard_core::error::{AppError, Result};
use portguard_core::time::now_ms;
use std::path::{Path, PathBuf};

/// 首次运行写入的配置模板头部注释。
const TEMPLATE_HEADER: &str = r#"# PortGuard 配置文件
# ---------------------------------------------------------------
# 修改后保存即可，面板会在下次「保存设置」时读取本文件。
# 列表项支持以下写法：
#   1.2.3.4            单个地址
#   1.2.3.0/24         网段
#   1.2.3.*            尾部通配（仅允许用在最后一段）
#   1.2.3.4-1.2.3.9    地址区间
# 以 # 开头的行会被忽略。
# ---------------------------------------------------------------

"#;

/// 本次加载的来由，供调用方写日志 / 提示用户。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadOutcome {
    /// 读取了已存在的正常配置。
    Existing,
    /// 文件不存在，已生成默认配置模板。
    CreatedDefault,
    /// 原文件损坏，已备份到指定路径并回退为默认配置。
    RecoveredFromBroken(PathBuf),
}

impl LoadOutcome {
    /// 是否发生了需要提示用户的异常（损坏恢复）。
    pub fn is_recovery(&self) -> bool {
        matches!(self, LoadOutcome::RecoveredFromBroken(_))
    }

    /// 供日志使用的中文说明。
    pub fn describe(&self) -> String {
        match self {
            LoadOutcome::Existing => "已加载现有配置".to_string(),
            LoadOutcome::CreatedDefault => "未找到配置文件，已生成默认配置模板".to_string(),
            LoadOutcome::RecoveredFromBroken(p) => format!(
                "配置文件损坏，已备份到 {} 并回退为默认配置，请人工核对",
                p.display()
            ),
        }
    }
}

/// 配置文件仓库。
#[derive(Clone, Debug)]
pub struct ConfigStore {
    path: PathBuf,
}

impl ConfigStore {
    pub fn new(path: impl Into<PathBuf>) -> ConfigStore {
        ConfigStore { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 加载配置，必要时生成模板或从损坏状态恢复。
    ///
    /// 本函数**不会**因为文件损坏而返回 Err：程序必须能起来，
    /// 恢复动作通过 `LoadOutcome` 如实上报。
    /// 但模板写盘失败属于真实故障，会返回 Err。
    pub fn load_or_create(&self) -> Result<(Config, LoadOutcome)> {
        if !self.path.exists() {
            let cfg = Config::with_defaults();
            self.save(&cfg)?;
            return Ok((cfg, LoadOutcome::CreatedDefault));
        }

        let text = std::fs::read_to_string(&self.path)
            .map_err(|e| AppError::Config(format!("读取 {} 失败：{}", self.path.display(), e)))?;

        match Config::from_toml(&text) {
            Ok(cfg) => Ok((cfg, LoadOutcome::Existing)),
            Err(_) => {
                let backup = self.backup_broken()?;
                let cfg = Config::with_defaults();
                self.save(&cfg)?;
                Ok((cfg, LoadOutcome::RecoveredFromBroken(backup)))
            }
        }
    }

    /// 保存配置（原子写入，防止断电留下半截文件）。
    pub fn save(&self, cfg: &Config) -> Result<()> {
        let mut cfg = cfg.clone();
        cfg.normalize();

        let errs = cfg.validate();
        if !errs.is_empty() {
            return Err(AppError::Config(format!("配置校验失败：{}", errs.join("；"))));
        }

        if let Some(dir) = self.path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)
                    .map_err(|e| AppError::Config(format!("创建目录 {} 失败：{}", dir.display(), e)))?;
            }
        }

        let mut text = String::from(TEMPLATE_HEADER);
        text.push_str(&cfg.to_toml()?);
        write_atomic(&self.path, &text)
    }

    /// 把损坏的配置文件改名备份，返回备份路径。
    fn backup_broken(&self) -> Result<PathBuf> {
        let ts = now_ms();
        let backup = self
            .path
            .with_file_name(format!("config.toml.broken-{}", ts));
        std::fs::rename(&self.path, &backup).map_err(|e| {
            AppError::Config(format!("备份损坏配置到 {} 失败：{}", backup.display(), e))
        })?;
        Ok(backup)
    }
}

/// 原子写入：先写同目录临时文件再 rename 覆盖。
///
/// 直接截断写目标文件的话，进程在写一半时被强杀会留下半截 TOML，
/// 下次启动就会走「配置损坏」的恢复路径。
fn write_atomic(path: &Path, text: &str) -> Result<()> {
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, text)
        .map_err(|e| AppError::Config(format!("写入临时文件 {} 失败：{}", tmp.display(), e)))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| AppError::Config(format!("替换 {} 失败：{}", path.display(), e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pg_cfg_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn 首次运行生成模板且可再次加载() {
        let d = tmpdir("first");
        let store = ConfigStore::new(d.join("config.toml"));
        let (cfg, outcome) = store.load_or_create().unwrap();
        assert_eq!(outcome, LoadOutcome::CreatedDefault);
        assert_eq!(cfg.protect.tcp.ports, vec![3389]);
        assert!(store.path().exists());

        let text = std::fs::read_to_string(store.path()).unwrap();
        assert!(text.starts_with("# PortGuard 配置文件"));

        let (again, outcome2) = store.load_or_create().unwrap();
        assert_eq!(outcome2, LoadOutcome::Existing);
        assert_eq!(again.protect.tcp.ports, vec![3389]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn 保存后重新加载内容一致() {
        let d = tmpdir("save");
        let store = ConfigStore::new(d.join("config.toml"));
        let (_, _) = store.load_or_create().unwrap();

        let mut cfg = Config::with_defaults();
        cfg.lists.whitelist = vec!["192.168.1.*".to_string()];
        cfg.ban.duration_seconds = 120;
        store.save(&cfg).unwrap();

        let (back, outcome) = store.load_or_create().unwrap();
        assert_eq!(outcome, LoadOutcome::Existing);
        assert_eq!(back.lists.whitelist, vec!["192.168.1.*"]);
        assert_eq!(back.ban.duration_seconds, 120);
        assert!(!store.path().with_extension("toml.tmp").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn 损坏配置被备份而非丢弃() {
        let d = tmpdir("broken");
        let _ = std::fs::create_dir_all(&d);
        let p = d.join("config.toml");
        std::fs::write(&p, "这不是 TOML [[[").unwrap();

        let store = ConfigStore::new(&p);
        let (cfg, outcome) = store.load_or_create().unwrap();

        assert!(outcome.is_recovery());
        assert!(outcome.describe().contains("损坏"));
        match outcome {
            LoadOutcome::RecoveredFromBroken(bak) => {
                assert!(bak.exists(), "损坏文件必须留下备份供人工核对");
                assert_eq!(std::fs::read_to_string(&bak).unwrap(), "这不是 TOML [[[");
            }
            _ => panic!("预期为恢复路径"),
        }
        // 回退到默认配置，且程序仍可正常启动
        assert_eq!(cfg.protect.tcp.ports, vec![3389]);
        assert!(p.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn 非法配置拒绝保存() {
        let d = tmpdir("invalid");
        let store = ConfigStore::new(d.join("config.toml"));
        let mut cfg = Config::with_defaults();
        cfg.lists.whitelist = vec!["不是IP".to_string()];
        let err = store.save(&cfg);
        assert!(err.is_err(), "含非法名单的配置不允许写入磁盘");
        assert!(err.unwrap_err().to_string().contains("白名单"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn 保存时自动规范化() {
        let d = tmpdir("normalize");
        let store = ConfigStore::new(d.join("config.toml"));
        let mut cfg = Config::with_defaults();
        cfg.protect.tcp.ports = vec![3389, 22, 22, 0];
        cfg.lists.blacklist = vec!["  ".to_string(), "1.2.3.4".to_string()];
        store.save(&cfg).unwrap();
        let (back, _) = store.load_or_create().unwrap();
        assert_eq!(back.protect.tcp.ports, vec![22, 3389]);
        assert_eq!(back.lists.blacklist, vec!["1.2.3.4"]);
        let _ = std::fs::remove_dir_all(&d);
    }
}
