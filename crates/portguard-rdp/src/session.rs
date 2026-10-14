//! WTS 会话查询与断开。
//!
//! 本模块只做最薄的一层封装：查询会话列表、取客户端计算机名、断开会话。
//! 判断「该不该断」交给 `policy`，便于纯逻辑单元测试。

use portguard_core::error::{AppError, Result};
use windows::Win32::Foundation::BOOL;
use windows::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSDisconnectSession, WTSEnumerateSessionsW, WTSFreeMemory,
    WTSQuerySessionInformationW, WTSActive, WTSClientName, WTSConnected, WTSDisconnected, WTSIdle,
    WTSListen, WTSUserName, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW,
};

/// 会话连接状态（只保留业务关心的几种）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// 已登录且在前台活动。
    Active,
    /// 已连接但未激活（例如被本地控制台抢占）。
    Connected,
    /// 已断开（用户仍保持登录，会话挂起）。
    Disconnected,
    /// 空闲监听（尚未有用户登录）。
    Idle,
    /// 监听器本身。
    Listen,
    /// 其他状态，保留原始值。
    Other(i32),
}

impl SessionState {
    fn from_raw(v: i32) -> SessionState {
        let raw = windows::Win32::System::RemoteDesktop::WTS_CONNECTSTATE_CLASS(v);
        if raw == WTSActive {
            SessionState::Active
        } else if raw == WTSConnected {
            SessionState::Connected
        } else if raw == WTSDisconnected {
            SessionState::Disconnected
        } else if raw == WTSIdle {
            SessionState::Idle
        } else if raw == WTSListen {
            SessionState::Listen
        } else {
            SessionState::Other(v)
        }
    }

    /// 是否是一个「有人正在使用」的会话。
    pub fn is_occupied(&self) -> bool {
        matches!(self, SessionState::Active | SessionState::Connected)
    }

    pub fn label(&self) -> &'static str {
        match self {
            SessionState::Active => "活动",
            SessionState::Connected => "已连接",
            SessionState::Disconnected => "已断开",
            SessionState::Idle => "空闲",
            SessionState::Listen => "监听",
            SessionState::Other(_) => "未知",
        }
    }
}

/// 一个终端服务会话。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    pub session_id: u32,
    /// 工作站名（如 `RDP-Tcp#12`、`Console`）。
    pub station: String,
    pub state: SessionState,
    /// 客户端计算机名。**本地控制台会话为空**，RDP 会话为发起端的机器名。
    pub client_name: Option<String>,
    pub user_name: Option<String>,
}

impl SessionInfo {
    /// 是否来自远程桌面。
    ///
    /// 判定依据是客户端名是否存在：只有远程会话才带客户端标识，
    /// 控制台会话（`Console`）没有。
    pub fn is_remote(&self) -> bool {
        self.client_name.as_deref().map(|s| !s.is_empty()).unwrap_or(false)
    }
}

/// 枚举本机全部终端服务会话。
pub fn enumerate() -> Result<Vec<SessionInfo>> {
    let mut raw: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count: u32 = 0;

    unsafe {
        WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut raw, &mut count)
            .map_err(|e| AppError::WindowsApi {
                api: "WTSEnumerateSessionsW",
                code: e.code().0 as u32,
            })?;
    }

    if raw.is_null() {
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity(count as usize);
    // 长度已知的裸数组切片；随后必须 WTSFreeMemory，故用闭包收口以防提前 return 泄漏。
    let result = unsafe {
        let slice = std::slice::from_raw_parts(raw, count as usize);
        for item in slice {
            let station = pwstr_to_string(item.pWinStationName).unwrap_or_default();
            out.push(SessionInfo {
                session_id: item.SessionId,
                station,
                state: SessionState::from_raw(item.State.0),
                client_name: query_string(item.SessionId, WTSClientName),
                user_name: query_string(item.SessionId, WTSUserName),
            });
        }
        Ok(out)
    };

    unsafe {
        WTSFreeMemory(raw as *mut core::ffi::c_void);
    }
    result
}

/// 查询指定会话的字符串信息（无值或失败时返回 `None`）。
fn query_string(session_id: u32, class: windows::Win32::System::RemoteDesktop::WTS_INFO_CLASS) -> Option<String> {
    let mut buffer = windows::core::PWSTR::null();
    let mut bytes: u32 = 0;

    unsafe {
        if WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session_id, class, &mut buffer, &mut bytes)
            .is_err()
        {
            return None;
        }
        if buffer.is_null() || bytes < 2 {
            if !buffer.is_null() {
                WTSFreeMemory(buffer.0 as *mut core::ffi::c_void);
            }
            return None;
        }

        // 按返回的字节数取切片，而不是依赖 to_string() 的 NUL 扫描，
        // 这样无论 WTS 是否保证结尾 NUL 都不会越界读。
        let len = (bytes / 2) as usize;
        let units = std::slice::from_raw_parts(buffer.0 as *const u16, len);
        let end = units.iter().position(|&c| c == 0).unwrap_or(units.len());
        let text = String::from_utf16_lossy(&units[..end]);

        WTSFreeMemory(buffer.0 as *mut core::ffi::c_void);
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }
}

/// 本进程所在会话号。
pub fn current_session_id() -> Option<u32> {
    let mut id: u32 = 0;
    unsafe {
        let pid = windows::Win32::System::Threading::GetCurrentProcessId();
        ProcessIdToSessionId(pid, &mut id).ok()?;
    }
    Some(id)
}

/// 查询指定会话的 ID 是否有效（存在）。
pub fn session_exists(session_id: u32) -> Result<bool> {
    Ok(enumerate()?.iter().any(|s| s.session_id == session_id))
}

/// 断开指定会话。
///
/// `wait = true` 时等待断开完成；本程序用 `false`，避免在判定线程上阻塞。
pub fn disconnect(session_id: u32, wait: bool) -> Result<()> {
    // 保护性校验：绝不允许断开自己的会话，否则程序会把自己踢下线。
    if let Some(self_id) = current_session_id() {
        if self_id == session_id {
            return Err(AppError::Other(format!(
                "拒绝断开本程序所在的会话 {}",
                session_id
            )));
        }
    }

    unsafe {
        WTSDisconnectSession(WTS_CURRENT_SERVER_HANDLE, session_id, BOOL::from(wait)).map_err(|e| {
            AppError::WindowsApi {
                api: "WTSDisconnectSession",
                code: e.code().0 as u32,
            }
        })
    }
}

/// 纯函数：把 PWSTR 转为 String，空指针返回 `None`。
unsafe fn pwstr_to_string(p: windows::core::PWSTR) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let mut len = 0usize;
    while *p.0.add(len) != 0 {
        len += 1;
        // 防御性上限，避免异常指针导致死循环
        if len > 4096 {
            break;
        }
    }
    if len == 0 {
        return None;
    }
    let units = std::slice::from_raw_parts(p.0, len);
    Some(String::from_utf16_lossy(units))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 会话状态映射正确() {
        assert_eq!(SessionState::from_raw(0), SessionState::Active);
        assert_eq!(SessionState::from_raw(1), SessionState::Connected);
        assert_eq!(SessionState::from_raw(4), SessionState::Disconnected);
        assert_eq!(SessionState::from_raw(5), SessionState::Idle);
        assert_eq!(SessionState::from_raw(6), SessionState::Listen);
        assert_eq!(SessionState::from_raw(99), SessionState::Other(99));
    }

    #[test]
    fn 仅活动与会话视为占用中() {
        assert!(SessionState::Active.is_occupied());
        assert!(SessionState::Connected.is_occupied());
        assert!(!SessionState::Disconnected.is_occupied());
        assert!(!SessionState::Idle.is_occupied());
        assert!(!SessionState::Other(9).is_occupied());
    }

    #[test]
    fn 本地控制台会话不算远程() {
        let s = SessionInfo {
            session_id: 1,
            station: "Console".to_string(),
            state: SessionState::Active,
            client_name: None,
            user_name: Some("Administrator".to_string()),
        };
        assert!(!s.is_remote(), "控制台会话没有客户端名，绝不能被当作远程会话处理");

        let r = SessionInfo {
            client_name: Some("DEV-PC".to_string()),
            ..s.clone()
        };
        assert!(r.is_remote());
    }

    #[test]
    fn 空客户端名不算远程() {
        let s = SessionInfo {
            session_id: 2,
            station: "RDP-Tcp#3".to_string(),
            state: SessionState::Active,
            client_name: Some(String::new()),
            user_name: None,
        };
        assert!(!s.is_remote());
    }

    #[test]
    fn 枚举本机会话可正常调用() {
        // 真实系统调用；结果取决于运行环境，只要求不 panic 且数据自洽。
        let list = enumerate().unwrap();
        let mut ids: Vec<u32> = list.iter().map(|s| s.session_id).collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total, "同一会话号不应重复出现");
    }

    #[test]
    fn 拒绝断开自身会话() {
        let me = current_session_id().unwrap();
        let r = disconnect(me, false);
        assert!(r.is_err(), "断开自身会话必须被拒绝，否则程序会把自己踢下线");
        assert!(r.unwrap_err().to_string().contains("拒绝"));
    }
}
