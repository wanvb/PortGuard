//! Windows 原始套接字抓包。
//!
//! 严格复现原程序的行为链（规范 1.2，禁止未经验证替换方案）：
//!
//! ```text
//! WSAStartup
//!   → socket(AF_INET, SOCK_RAW, IPPROTO_IP)
//!   → bind(本机 IP)
//!   → WSAIoctl(SIO_RCVALL, 1)
//!   → recv() 循环
//!   → IPv4 / TCP / UDP 解析
//!   → PacketInfo
//!   → closesocket / WSACleanup
//! ```
//!
//! 设计要点：
//! - 套接字创建、bind、SIO_RCVALL 全部在**调用线程**完成，
//!   因此「权限不足 / 网卡不可用」能立刻返回错误，而不是在后台线程里静默失败；
//! - 只有阻塞的 `recv` 循环放进后台线程；
//! - 通过 `SO_RCVTIMEO` 让 `recv` 周期性醒来，从而能响应停止请求。

use crate::parser::parse_ethernet_or_ip;
use portguard_core::error::{AppError, Result};
use portguard_core::model::Ip;
use portguard_core::time::now_ms;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// 抓包回调收到的事件。
pub use crate::parser::ParsedPacket;

/// 抓包句柄。析构时自动停止并回收线程。
pub struct CaptureHandle {
    running: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
    local_ip: Ip,
}

impl CaptureHandle {
    /// 请求停止并等待线程退出（最长约 500 ms）。
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(h) = self.join.take() {
            // 线程内部已处理所有错误，这里不 panic，仅等待回收。
            let _ = h.join();
        }
    }

    /// 是否仍在运行。
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
            && self.join.as_ref().map(|h| !h.is_finished()).unwrap_or(false)
    }

    /// 当前监听的地址。
    pub fn local_ip(&self) -> Ip {
        self.local_ip
    }
}

impl Drop for CaptureHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use crate::parser::ParsedPacket;
    use windows::Win32::Networking::WinSock::{
        bind, closesocket, recv, setsockopt, socket, WSAGetLastError, WSADATA, WSACleanup,
        WSAStartup, AF_INET, INVALID_SOCKET, IPPROTO_IP, SEND_RECV_FLAGS, SOCKADDR, SOCKADDR_IN,
        SOCK_RAW, SOL_SOCKET, SO_RCVTIMEO, WSAEINTR, WSAETIMEDOUT, WSAIoctl, SIO_RCVALL,
    };

    /// 收包缓冲：单包最大 65535 字节。
    const RECV_BUFFER: usize = 65_536;

    /// `recv` 超时，单位毫秒。决定停止监听的最大延迟。
    const RECV_TIMEOUT_MS: u32 = 500;

    /// 允许把 `SOCKET` 移动到后台线程。
    ///
    /// 安全性说明：`SOCKET` 是一个不透明的句柄值（`usize`），
    /// 跨线程传递句柄本身是 Winsock 允许的；这里仅在本模块内、
    /// 且保证「只有一个线程调用 recv」的前提下使用。
    struct SendSocket(windows::Win32::Networking::WinSock::SOCKET);
    unsafe impl Send for SendSocket {}

    /// 启动抓包。
    ///
    /// 前置条件：调用进程必须具备管理员权限并已选择可用的本机 IPv4 地址。
    /// 返回 `Err` 表示监听**没有**启动成功，调用方必须如实展示。
    ///
    /// 这里按 C 头文件的顺序逐字段填充 Win32 结构体（`SOCKADDR_IN` 等），
    /// 比结构体字面量更贴近 `bind` 的原始写法，因此豁免 clippy 的建议。
    #[allow(clippy::field_reassign_with_default)]
    pub fn start<P, E>(local_ip: Ip, mut on_packet: P, mut on_error: E) -> Result<CaptureHandle>
    where
        P: FnMut(ParsedPacket) + Send + 'static,
        E: FnMut(String) + Send + 'static,
    {
        let mut wsa = WSADATA::default();
        // MAKEWORD(2, 2)
        let ret = unsafe { WSAStartup(0x0202, &mut wsa) };
        if ret != 0 {
            return Err(AppError::Socket(format!(
                "WSAStartup 失败，错误码 {}",
                ret
            )));
        }

        // 从这一步开始，任何失败都必须先 WSACleanup 再返回，避免 Winsock 引用计数泄漏。
        let sock = unsafe { socket(AF_INET.0 as i32, SOCK_RAW, IPPROTO_IP.0) };
        if sock == INVALID_SOCKET {
            let code = unsafe { WSAGetLastError() }.0;
            unsafe { WSACleanup() };
            return Err(AppError::Socket(format!(
                "创建原始套接字失败（错误码 {}）。请确认以管理员身份运行。",
                code
            )));
        }

        // bind 到指定本机地址。
        let mut sin = SOCKADDR_IN::default();
        sin.sin_family = AF_INET;
        sin.sin_port = 0;
        sin.sin_addr.S_un.S_addr = u32::to_be(u32::from(local_ip));
        let bind_ret = unsafe {
            bind(
                sock,
                &sin as *const SOCKADDR_IN as *const SOCKADDR,
                core::mem::size_of::<SOCKADDR_IN>() as i32,
            )
        };
        if bind_ret != 0 {
            let code = unsafe { WSAGetLastError() }.0;
            unsafe { closesocket(sock) };
            unsafe { WSACleanup() };
            return Err(AppError::Socket(format!(
                "绑定网卡 {} 失败（错误码 {}）",
                local_ip, code
            )));
        }

        // 设置接收超时，使 recv 能周期性返回，从而响应停止请求。
        let timeout = RECV_TIMEOUT_MS.to_le_bytes();
        let opt_ret = unsafe {
            setsockopt(
                sock,
                SOL_SOCKET,
                SO_RCVTIMEO,
                Some(&timeout),
            )
        };
        if opt_ret != 0 {
            let code = unsafe { WSAGetLastError() }.0;
            unsafe { closesocket(sock) };
            unsafe { WSACleanup() };
            return Err(AppError::Socket(format!(
                "设置 SO_RCVTIMEO 失败（错误码 {}）",
                code
            )));
        }

        // SIO_RCVALL：接收该网卡上的全部 IPv4 流量。
        let rcvall: u32 = 1;
        let mut bytes_returned: u32 = 0;
        let ioctl_ret = unsafe {
            WSAIoctl(
                sock,
                SIO_RCVALL,
                Some(&rcvall as *const u32 as *const core::ffi::c_void),
                core::mem::size_of::<u32>() as u32,
                None,
                0,
                &mut bytes_returned,
                None,
                None,
            )
        };
        if ioctl_ret != 0 {
            let code = unsafe { WSAGetLastError() }.0;
            unsafe { closesocket(sock) };
            unsafe { WSACleanup() };
            return Err(AppError::Socket(format!(
                "启用混杂模式 SIO_RCVALL 失败（错误码 {}）。请确认以管理员身份运行且所选网卡可用。",
                code
            )));
        }

        let running = Arc::new(AtomicBool::new(true));
        let running_thread = Arc::clone(&running);
        let sock_thread = SendSocket(sock);

        let join = std::thread::Builder::new()
            .name("portguard-capture".to_string())
            .spawn(move || {
                let s = sock_thread;
                let mut buf = vec![0u8; RECV_BUFFER];
                while running_thread.load(Ordering::SeqCst) {
                    let n = unsafe { recv(s.0, &mut buf, SEND_RECV_FLAGS(0)) };
                    if n > 0 {
                        let len = n as usize;
                        match parse_ethernet_or_ip(&buf[..len]) {
                            Ok(mut parsed) => {
                                parsed.info.timestamp_ms = now_ms();
                                on_packet(parsed);
                            }
                            Err(e) => {
                                // 畸形包、分片包、非 IPv4 包都属于常态，不当作错误上报，
                                // 否则日志会被噪声淹没。
                                let _ = e;
                            }
                        }
                        continue;
                    }
                    let code = unsafe { WSAGetLastError() }.0;
                    if code == WSAETIMEDOUT.0 {
                        continue; // 正常超时，回到循环顶部检查停止标志
                    }
                    if code == WSAEINTR.0 {
                        continue;
                    }
                    if n == 0 {
                        break;
                    }
                    on_error(format!("recv 失败（错误码 {}）", code));
                    break;
                }
                unsafe { closesocket(s.0) };
                unsafe { WSACleanup() };
            })
            .map_err(|e| AppError::Socket(format!("创建抓包线程失败：{}", e)))?;

        Ok(CaptureHandle {
            running,
            join: Some(join),
            local_ip,
        })
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    use crate::parser::ParsedPacket;

    /// 非 Windows 平台直接拒绝，保证调用方逻辑一致。
    pub fn start<P, E>(_local_ip: Ip, _on_packet: P, _on_error: E) -> Result<CaptureHandle>
    where
        P: FnMut(ParsedPacket) + Send + 'static,
        E: FnMut(String) + Send + 'static,
    {
        Err(AppError::Socket(
            "抓包功能仅在 Windows 上可用".to_string(),
        ))
    }
}

/// 启动抓包（详见 [`platform`] 模块说明）。
pub fn start<P, E>(local_ip: Ip, on_packet: P, on_error: E) -> Result<CaptureHandle>
where
    P: FnMut(ParsedPacket) + Send + 'static,
    E: FnMut(String) + Send + 'static,
{
    platform::start(local_ip, on_packet, on_error)
}
