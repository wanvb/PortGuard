//! 日志器：内存环形缓冲 + 后台线程落盘。
//!
//! 规范 42 明确禁止在抓包线程里同步写磁盘。这里的做法是：
//!
//! ```text
//! 业务线程                    后台写盘线程
//!   log()                        recv_timeout(500ms)
//!    ├─ 写内存环形缓冲（供面板读取）   ├─ 批量写入 BufWriter
//!    └─ try_send(通道)  ────────→    └─ 按大小滚动
//! ```
//!
//! 通道写满时**丢弃文件副本但保留内存副本**：日志绝不允许反压业务线程。

use portguard_core::error::{AppError, Result};
use portguard_core::logging::{Level, LogBuffer, LogLine};
use portguard_core::time::now_ms;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// 单个日志文件的最大字节数，超过后滚动为 `.1`。
const MAX_LOG_BYTES: u64 = 16 * 1024 * 1024;

/// 通道容量。写满即丢弃文件副本，避免阻塞业务线程。
const CHANNEL_CAPACITY: usize = 4096;

/// 日志器。
pub struct Logger {
    buffer: Arc<Mutex<LogBuffer>>,
    level: Arc<AtomicU8>,
    sender: Option<SyncSender<LogLine>>,
    join: Option<JoinHandle<()>>,
    file: PathBuf,
    /// 因通道写满而未能落盘的行数（健康度指标）。
    dropped: Arc<AtomicU64>,
}

fn level_to_u8(l: Level) -> u8 {
    match l {
        Level::Trace => 0,
        Level::Debug => 1,
        Level::Info => 2,
        Level::Warn => 3,
        Level::Error => 4,
    }
}

fn u8_to_level(v: u8) -> Level {
    match v {
        0 => Level::Trace,
        1 => Level::Debug,
        3 => Level::Warn,
        4 => Level::Error,
        _ => Level::Info,
    }
}

impl Logger {
    /// 启动日志器。
    pub fn start(file: &Path, level: Level, capacity: usize) -> Result<Logger> {
        if let Some(dir) = file.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir).map_err(|e| {
                    AppError::Storage(format!("创建日志目录 {} 失败：{}", dir.display(), e))
                })?;
            }
        }

        let (tx, rx) = sync_channel::<LogLine>(CHANNEL_CAPACITY);
        let buffer = Arc::new(Mutex::new(LogBuffer::new(capacity)));
        let dropped = Arc::new(AtomicU64::new(0));
        let path = file.to_path_buf();
        let dropped_thread = Arc::clone(&dropped);

        let join = std::thread::Builder::new()
            .name("portguard-log".to_string())
            .spawn(move || writer_loop(rx, path, dropped_thread))
            .map_err(|e| AppError::Storage(format!("创建日志线程失败：{}", e)))?;

        Ok(Logger {
            buffer,
            level: Arc::new(AtomicU8::new(level_to_u8(level))),
            sender: Some(tx),
            join: Some(join),
            file: file.to_path_buf(),
            dropped,
        })
    }

    /// 写一行日志。
    pub fn log(&self, level: Level, message: impl Into<String>) {
        if level_to_u8(level) < self.level.load(Ordering::Relaxed) {
            return;
        }
        let line = LogLine {
            ts_ms: now_ms(),
            level,
            message: message.into(),
        };
        // 内存副本必定写入：面板要能立刻看到。
        if let Ok(mut b) = self.buffer.lock() {
            b.push(line.clone());
        }
        if let Some(tx) = &self.sender {
            match tx.try_send(line) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                }
                Err(TrySendError::Disconnected(_)) => {}
            }
        }
    }

    pub fn info(&self, m: impl Into<String>) {
        self.log(Level::Info, m);
    }
    pub fn warn(&self, m: impl Into<String>) {
        self.log(Level::Warn, m);
    }
    pub fn error(&self, m: impl Into<String>) {
        self.log(Level::Error, m);
    }
    pub fn debug(&self, m: impl Into<String>) {
        self.log(Level::Debug, m);
    }

    /// 取最近若干行。
    pub fn tail(&self, limit: usize) -> Vec<LogLine> {
        self.buffer
            .lock()
            .map(|b| b.tail(limit))
            .unwrap_or_default()
    }

    /// 当前内存中的日志行数。
    pub fn buffered_lines(&self) -> usize {
        self.buffer.lock().map(|b| b.len()).unwrap_or(0)
    }

    /// 因通道拥塞而丢弃的文件日志行数。
    pub fn dropped_lines(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// 动态调整级别。
    pub fn set_level(&self, level: Level) {
        self.level.store(level_to_u8(level), Ordering::Relaxed);
    }

    pub fn level(&self) -> Level {
        u8_to_level(self.level.load(Ordering::Relaxed))
    }

    /// 日志文件路径。
    pub fn file(&self) -> &Path {
        &self.file
    }

    /// 停止并冲刷。
    pub fn stop(&mut self) {
        // 关闭通道 → 写盘线程收到 Disconnected → 冲刷退出。
        self.sender = None;
        if let Some(h) = self.join.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Logger {
    fn drop(&mut self) {
        self.stop();
    }
}

/// 后台写盘循环。
fn writer_loop(rx: Receiver<LogLine>, path: PathBuf, dropped: Arc<AtomicU64>) {
    let mut file = match open_log(&path) {
        Ok(f) => f,
        Err(_) => return, // 无法打开日志文件时静默降级为「仅内存日志」
    };
    let mut written: u64 = 0;
    let mut pending: Vec<LogLine> = Vec::with_capacity(128);

    loop {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(line) => {
                pending.push(line);
                // 批量累积，减少系统调用。
                while let Ok(more) = rx.try_recv() {
                    pending.push(more);
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                // 退出前把剩余内容冲刷干净。
                flush_lines(&mut file, &mut pending, &mut written, &path, &dropped);
                let _ = file.flush();
                return;
            }
        }
        flush_lines(&mut file, &mut pending, &mut written, &path, &dropped);
    }
}

/// 把累积的行写入文件，必要时滚动。
fn flush_lines(
    file: &mut std::fs::File,
    pending: &mut Vec<LogLine>,
    written: &mut u64,
    path: &Path,
    _dropped: &Arc<AtomicU64>,
) {
    if pending.is_empty() {
        return;
    }
    for line in pending.drain(..) {
        let text = line.render();
        if writeln!(file, "{}", text).is_err() {
            continue;
        }
        *written += text.len() as u64 + 2;
    }
    let _ = file.flush();

    if *written >= MAX_LOG_BYTES {
        let _ = file.flush();
        let rolled = path.with_extension("log.1");
        // 滚动失败也无妨，继续写当前文件即可。
        if std::fs::rename(path, rolled).is_ok() {
            if let Ok(f) = open_log(path) {
                *file = f;
                *written = 0;
            }
        } else {
            *written = 0;
        }
    }
}

fn open_log(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("pg_log_{}_{}.log", name, std::process::id()))
    }

    #[test]
    fn 日志能落盘并可按行读取() {
        let p = tmp("basic");
        let _ = std::fs::remove_file(&p);
        {
            let logger = Logger::start(&p, Level::Info, 100).unwrap();
            logger.info("程序启动");
            logger.warn("测试告警");
            // stop() 会冲刷
        }
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("程序启动"));
        assert!(text.contains("[WARN ]"));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn 低于级别的日志被过滤() {
        let p = tmp("level");
        let _ = std::fs::remove_file(&p);
        let logger = Logger::start(&p, Level::Warn, 100).unwrap();
        logger.debug("不该出现");
        logger.info("不该出现");
        logger.error("应该出现");
        assert_eq!(logger.tail(10).len(), 1);
        assert_eq!(logger.tail(10)[0].message, "应该出现");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn 内存缓冲遵守容量上限() {
        let p = tmp("cap");
        let _ = std::fs::remove_file(&p);
        let logger = Logger::start(&p, Level::Info, 10).unwrap();
        for i in 0..50 {
            logger.info(format!("第{}行", i));
        }
        assert_eq!(logger.buffered_lines(), 10);
        assert_eq!(logger.tail(1)[0].message, "第49行");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn 级别可动态调整() {
        let p = tmp("dynlevel");
        let _ = std::fs::remove_file(&p);
        let logger = Logger::start(&p, Level::Error, 100).unwrap();
        logger.warn("被过滤");
        assert_eq!(logger.buffered_lines(), 0);
        logger.set_level(Level::Debug);
        logger.debug("现在可见");
        assert_eq!(logger.buffered_lines(), 1);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn 目录不存在时自动创建() {
        let dir = std::env::temp_dir().join(format!("pg_log_dir_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = dir.join("nested").join("a.log");
        let logger = Logger::start(&p, Level::Info, 10).unwrap();
        logger.info("hi");
        drop(logger);
        assert!(p.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
