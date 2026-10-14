//! 日志模型与内存环形缓冲。
//!
//! 本模块只负责「日志长什么样」与「最近 N 行保存在哪」。
//! 真正的落盘由 `portguard-storage` 的独立线程完成——
//! 规范 42 明确禁止在抓包线程里同步写磁盘。

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// 日志级别。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    /// 固定宽度的大写标签，保证日志文件对齐。
    pub fn label(&self) -> &'static str {
        match self {
            Level::Trace => "TRACE",
            Level::Debug => "DEBUG",
            Level::Info => "INFO ",
            Level::Warn => "WARN ",
            Level::Error => "ERROR",
        }
    }

    /// 从配置字符串解析，无法识别时回落到 `Info`。
    pub fn parse(s: &str) -> Level {
        match s.trim().to_ascii_lowercase().as_str() {
            "trace" => Level::Trace,
            "debug" => Level::Debug,
            "warn" | "warning" => Level::Warn,
            "error" => Level::Error,
            _ => Level::Info,
        }
    }
}

/// 一行日志。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogLine {
    /// Unix 纪元毫秒。
    pub ts_ms: u64,
    pub level: Level,
    /// 已格式化好的人类可读文本（不含时间与级别前缀）。
    pub message: String,
}

impl LogLine {
    /// 渲染成单行文本。
    pub fn render(&self) -> String {
        format!(
            "{} [{}] {}",
            crate::time::format_ms(self.ts_ms),
            self.level.label(),
            self.message
        )
    }
}

/// 固定容量的日志环形缓冲，供 Web 面板读取最近日志。
#[derive(Debug)]
pub struct LogBuffer {
    lines: VecDeque<LogLine>,
    capacity: usize,
}

impl Default for LogBuffer {
    fn default() -> Self {
        LogBuffer::new(2000)
    }
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Self {
        LogBuffer {
            lines: VecDeque::with_capacity(capacity.min(4096)),
            capacity: capacity.max(1),
        }
    }

    /// 追加一行，超出容量时丢弃最旧的一行。
    pub fn push(&mut self, line: LogLine) {
        while self.lines.len() >= self.capacity {
            self.lines.pop_front();
        }
        self.lines.push_back(line);
    }

    /// 取最近 `limit` 行，按时间升序返回。
    pub fn tail(&self, limit: usize) -> Vec<LogLine> {
        let n = limit.min(self.lines.len());
        self.lines
            .iter()
            .skip(self.lines.len() - n)
            .cloned()
            .collect()
    }

    pub fn len(&self) -> usize {
        self.lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    pub fn clear(&mut self) {
        self.lines.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(ts: u64, msg: &str) -> LogLine {
        LogLine {
            ts_ms: ts,
            level: Level::Info,
            message: msg.to_string(),
        }
    }

    #[test]
    fn 超容量丢弃最旧行() {
        let mut b = LogBuffer::new(3);
        for i in 0..5 {
            b.push(line(i, &format!("第{}条", i)));
        }
        assert_eq!(b.len(), 3);
        let tail = b.tail(10);
        assert_eq!(tail[0].message, "第2条");
        assert_eq!(tail[2].message, "第4条");
    }

    #[test]
    fn tail返回最近若干行() {
        let mut b = LogBuffer::new(10);
        for i in 0..10 {
            b.push(line(i, &format!("m{}", i)));
        }
        let t = b.tail(3);
        assert_eq!(t.len(), 3);
        assert_eq!(t[0].message, "m7");
        assert_eq!(t[2].message, "m9");
    }

    #[test]
    fn 空缓冲取行返回空() {
        let b = LogBuffer::new(10);
        assert!(b.tail(5).is_empty());
    }

    #[test]
    fn 级别解析容错() {
        assert_eq!(Level::parse("WARN"), Level::Warn);
        assert_eq!(Level::parse("  debug "), Level::Debug);
        assert_eq!(Level::parse("随便写"), Level::Info);
        assert_eq!(Level::parse(""), Level::Info);
    }

    #[test]
    fn 渲染包含级别与时间() {
        let l = line(0, "程序启动");
        let s = l.render();
        assert!(s.contains("[INFO ]"));
        assert!(s.contains("程序启动"));
    }
}
