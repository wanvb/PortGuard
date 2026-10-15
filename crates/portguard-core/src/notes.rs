//! 端口 / 名单规则的备注（标识说明）。
//!
//! 备注是**纯展示**元数据：不参与端口匹配、名单解析、阈值判定与封停，也不参与
//! 配置校验（与地理位置 `location` 同一口径，规范 22）。它存在的唯一理由是回答
//! 「这个端口是谁在用、这条规则属于哪个业务」——服务器上 frp 穿透的端口一多，
//! 光看端口号根本分不清业务。
//!
//! 备注与端口 / 规则分开存储（平行映射），因此判定链路完全不感知它的存在：
//! 端口仍是 `Vec<u16>`，名单仍是 `Vec<String>`。
//!
//! 代价是必须做「孤儿清理」：端口或规则被删掉后，备注若不跟着走就会永远留在
//! `config.toml` 里越积越多，用户日后加回同一个端口还会看到过期备注。
//! 清理统一放在 [`normalize`] 里，由 `Config::normalize` 调用——保存配置、
//! 面板增删名单、手改配置文件三条路径都经过它，不必在每个入口各写一份。

use std::collections::BTreeMap;

/// 单条备注的字符上限。
///
/// 备注只是给人看的短标签，不设上限会让 `config.toml` 被长文本撑大；
/// 前端输入框同步有 `maxlength`，这里是防手工改配置文件的兜底。
pub const MAX_NOTE_CHARS: usize = 64;

/// 备注表：键 → 备注。
///
/// 键必须是字符串：TOML 的 map 键只能是字符串（toml 序列化器对整数键直接报错），
/// 因此端口以十进制字符串作键（`"3389"`），名单以规则原文作键（`"1.2.3.0/24"`，
/// 含 `.` `*` `/` 的键由写入器自动加引号）。
pub type Notes = BTreeMap<String, String>;

/// 清洗一条备注：剔除控制字符（含换行）、去首尾空白、按**字符**截断到上限。
///
/// 截断必须按字符而非字节：备注里写中文是常态，按字节切会切碎 UTF-8 序列。
pub fn clean(text: &str) -> String {
    let flat: String = text.chars().filter(|c| !c.is_control()).collect();
    let cut: String = flat.trim().chars().take(MAX_NOTE_CHARS).collect();
    cut.trim_end().to_string()
}

/// 规范化整张备注表：清洗每条 → 丢弃空备注 → 丢弃键已不在 `valid_keys` 中的孤儿。
pub fn normalize(notes: &mut Notes, valid_keys: &[String]) {
    notes.retain(|k, _| valid_keys.iter().any(|v| v == k));
    for value in notes.values_mut() {
        *value = clean(value);
    }
    notes.retain(|_, v| !v.is_empty());
}

/// 取一条备注；键不存在或备注为空时返回 `None`（调用方不必区分这两种情况）。
pub fn get<'a>(notes: &'a Notes, key: &str) -> Option<&'a str> {
    notes
        .get(key)
        .map(|s| s.as_str())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notes(pairs: &[(&str, &str)]) -> Notes {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn 清洗去掉空白与换行() {
        assert_eq!(clean("  张三的 frp\n"), "张三的 frp");
        assert_eq!(clean("第一行\r\n第二行"), "第一行第二行");
        assert_eq!(clean("\t\t"), "");
    }

    #[test]
    fn 超长备注按字符截断且不切碎中文() {
        let long = "备注".repeat(80);
        let cut = clean(&long);
        assert_eq!(cut.chars().count(), MAX_NOTE_CHARS);
        assert!(cut.starts_with("备注备注"));
    }

    #[test]
    fn 端口被删掉后备注一并清除() {
        let mut n = notes(&[("3389", "远程桌面"), ("22", "跳板机")]);
        normalize(&mut n, &["3389".to_string()]);
        assert_eq!(n.len(), 1);
        assert_eq!(get(&n, "3389"), Some("远程桌面"));
        assert_eq!(get(&n, "22"), None);
    }

    #[test]
    fn 空备注与纯空白备注不留在表里() {
        let mut n = notes(&[("3389", "   "), ("22", "跳板机")]);
        normalize(&mut n, &["3389".to_string(), "22".to_string()]);
        assert_eq!(n.len(), 1);
        assert!(n.contains_key("22"));
    }

    #[test]
    fn 备注为空串时视为没有备注() {
        let n = notes(&[("3389", "")]);
        assert_eq!(get(&n, "3389"), None);
        assert_eq!(get(&n, "22"), None);
    }
}
