//! 系统语言环境探测。
//!
//! 面板的界面语言设置为「跟随系统」时，用它决定显示中文还是英文。
//! 结果只探测一次并缓存：系统语言在进程运行期不会变，探测值由
//! `PanelMeta::system_language` 持有，面板每次请求 `/api/meta` 复用它。

use portguard_core::config::{LANGUAGE_EN, LANGUAGE_ZH};
use std::sync::OnceLock;
use windows::Win32::Globalization::{GetSystemDefaultUILanguage, GetUserDefaultUILanguage};

/// Win32 `LANG_CHINESE`：`MAKELANGID` 的低 10 位为中文时的取值。
const LANG_CHINESE: u16 = 0x04;
/// `MAKELANGID` 的主语言部分掩码。
const PRIMARY_LANG_MASK: u16 = 0x03FF;

static CACHED: OnceLock<&'static str> = OnceLock::new();

/// 本机界面语言：`"zh"` 或 `"en"`（只可能是 [`LANGUAGE_ZH`] / [`LANGUAGE_EN`]）。
///
/// 先取当前用户界面语言，取不到再退到系统安装语言；两者都取不到时按中文
/// （与 `PanelConfig::effective_language` 的回落口径一致）。探测不 panic：
/// 语言只影响界面文案，绝不该拖垮启动流程。
pub fn system_language() -> &'static str {
    CACHED.get_or_init(|| {
        let user = language_of(unsafe { GetUserDefaultUILanguage() });
        if user.is_empty() {
            let system = language_of(unsafe { GetSystemDefaultUILanguage() });
            if system.is_empty() {
                return LANGUAGE_ZH;
            }
            return system;
        }
        user
    })
}

/// `LANGID` → 界面语言标识的纯函数（可单测）。
///
/// 非中文一律算英文：本项目的界面只提供中英两种文案，德语 / 日语等环境
/// 用英文兜底比用中文更可读。返回空串表示探测值不可用（API 返回 0）。
pub fn language_of(langid: u16) -> &'static str {
    if langid == 0 {
        return "";
    }
    if langid & PRIMARY_LANG_MASK == LANG_CHINESE {
        LANGUAGE_ZH
    } else {
        LANGUAGE_EN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 语言标识按主语言归类() {
        // 0x0804 = 简体中文（中国大陆），0x0404 = 繁体中文（台湾）
        assert_eq!(language_of(0x0804), LANGUAGE_ZH);
        assert_eq!(language_of(0x0404), LANGUAGE_ZH);
        // 0x0409 = 英文（美国），0x0407 = 德文
        assert_eq!(language_of(0x0409), LANGUAGE_EN);
        assert_eq!(language_of(0x0407), LANGUAGE_EN);
        // 0 表示探测失败，交给调用方回退，不在这里瞎猜
        assert_eq!(language_of(0), "");
    }

    #[test]
    fn 系统语言探测结论自洽() {
        let lang = system_language();
        assert!(
            lang == LANGUAGE_ZH || lang == LANGUAGE_EN,
            "探测结果只能是中英之一，实际 {}",
            lang
        );
        // 缓存：多次调用必须是同一个值
        assert_eq!(lang, system_language());
    }
}
