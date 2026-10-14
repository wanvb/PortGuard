//! 地域信息记录。
//!
//! 数据库中的数据以 UTF-8 文本存放，格式固定为
//! `国家|省份|城市|ISP|国家代码`，例如：
//!
//! ```text
//! 中国|福建省|福州市|中国电信|CN
//! United States|California|0|Google LLC|US
//! Reserved|Reserved|Reserved|0|0
//! ```
//!
//! 其中 `0` 表示该字段无数据（常见于省份 / 城市 / ISP），
//! 而整条 `Reserved` 记录用于内网与保留地址段。

use crate::UNKNOWN;

/// 一条地域信息记录。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GeoRecord {
    /// 国家或地区。
    pub country: String,
    /// 省份 / 一级行政区。
    pub province: String,
    /// 城市。
    pub city: String,
    /// 运营商。
    pub isp: String,
    /// 国家代码；保留地址段为 `0`。
    pub code: String,
}

impl GeoRecord {
    /// 解析数据库中的一条文本记录。
    ///
    /// 字段不足按空串处理：库中个别记录只有 4 段，
    /// 缺字段不应让整条记录变成不可用。
    pub fn parse(text: &str) -> GeoRecord {
        let mut fields = text.split('|');
        GeoRecord {
            country: take(&mut fields),
            province: take(&mut fields),
            city: take(&mut fields),
            isp: take(&mut fields),
            code: take(&mut fields),
        }
    }

    /// 是否为内网 / 保留地址段。
    ///
    /// 数据库用 `Reserved` 标记这些网段（如 10.0.0.0/8、192.168.0.0/16），
    /// 直接展示 `Reserved` 对用户没有意义。
    pub fn is_reserved(&self) -> bool {
        self.country.eq_ignore_ascii_case("Reserved")
    }

    /// 生成面板展示文本：`国家 · 省份 · 城市 · ISP`。
    ///
    /// 空字段与占位 `0` 一律跳过；确实没有可用信息时返回「未知」。
    pub fn describe(&self) -> String {
        if self.is_reserved() {
            return "保留地址".to_string();
        }
        let mut parts: Vec<&str> = Vec::with_capacity(4);
        for field in [&self.country, &self.province, &self.city, &self.isp] {
            let value = field.trim();
            if value.is_empty() || value == "0" {
                continue;
            }
            parts.push(value);
        }
        if parts.is_empty() {
            return UNKNOWN.to_string();
        }
        parts.join(" · ")
    }
}

/// 取下一条字段并去掉首尾空白；不足时返回空串。
fn take<'a, I: Iterator<Item = &'a str>>(fields: &mut I) -> String {
    fields.next().unwrap_or("").trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 常规记录解析出五个字段() {
        let r = GeoRecord::parse("中国|福建省|福州市|中国电信|CN");
        assert_eq!(r.country, "中国");
        assert_eq!(r.province, "福建省");
        assert_eq!(r.city, "福州市");
        assert_eq!(r.isp, "中国电信");
        assert_eq!(r.code, "CN");
        assert!(!r.is_reserved());
    }

    #[test]
    fn 展示文本跳过占位零() {
        let r = GeoRecord::parse("United States|California|0|Google LLC|US");
        assert_eq!(r.describe(), "United States · California · Google LLC");
    }

    #[test]
    fn 保留地址段显示为保留地址() {
        let r = GeoRecord::parse("Reserved|Reserved|Reserved|0|0");
        assert!(r.is_reserved());
        assert_eq!(r.describe(), "保留地址");
    }

    #[test]
    fn 字段不足按空处理且不恐慌() {
        let r = GeoRecord::parse("中国");
        assert_eq!(r.country, "中国");
        assert_eq!(r.city, "");
        // 只剩国家时仍可用
        assert_eq!(r.describe(), "中国");
    }

    #[test]
    fn 无可用字段时展示为未知() {
        // 全为空 / 全为占位 0 的记录不能显示成空白，统一落到「未知」
        assert_eq!(GeoRecord::parse("|0|0||0").describe(), UNKNOWN);
        assert_eq!(GeoRecord::parse("").describe(), UNKNOWN);
    }
}
