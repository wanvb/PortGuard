//! 网卡枚举。
//!
//! 原程序使用 `GetAdaptersInfo`（仅 IPv4、已废弃）；Rust 版本改用
//! IP Helper 的 `GetAdaptersAddresses`，可拿到描述、运行状态与接口类型，
//! 且 Windows 7 起即可用（规范 12）。
//!
//! 与原有行为的**有意差异**：不再默认排除 VMware。是否显示虚拟网卡
//! 交给用户配置项 `network.include_virtual` 决定（规范 12 明确要求）。

use portguard_core::error::Result;
use portguard_core::model::Ip;

/// 一块网卡上的一个 IPv4 地址。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterInfo {
    /// IPv4 地址。
    pub ip: Ip,
    /// 子网前缀长度（0-32）。
    pub prefix_len: u8,
    /// 子网掩码（点分十进制）。
    pub mask: String,
    /// 网卡描述（驱动级友好名，通常比「本地连接」更具辨识度）。
    pub description: String,
    /// 连接名称（如「本地连接」）。
    pub friendly_name: String,
    /// 是否为虚拟网卡。
    pub is_virtual: bool,
    /// 是否处于 Up 状态。
    pub is_up: bool,
    /// 接口索引。
    pub if_index: u32,
}

impl AdapterInfo {
    /// 面板展示用文案：`[192.168.1.10] Intel(R) Ethernet Connection...`
    pub fn display(&self) -> String {
        format!("[{}] {}", self.ip, self.description)
    }

    /// 是否可用于抓包。
    ///
    /// 按规范 12 排除 `0.0.0.0` 与回环地址；虚拟网卡是否排除由调用方过滤。
    pub fn is_usable(&self) -> bool {
        !self.ip.is_unspecified() && !self.ip.is_loopback()
    }

    /// 根据前缀长度算出点分十进制掩码。
    pub fn mask_from_prefix(prefix_len: u8) -> String {
        let bits = prefix_len.min(32) as u32;
        let mask: u32 = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
        Ip::from(mask).to_string()
    }
}

/// 已知的虚拟网卡关键字。命中即视为虚拟网卡。
///
/// 这里只做**提示性分类**，不影响抓包正确性；
/// 用户可以通过 `include_virtual` 配置决定是否展示。
const VIRTUAL_HINTS: &[&str] = &[
    "vmware",
    "virtualbox",
    "hyper-v",
    "vethernet",
    "virtual",
    "loopback",
    "tap-",
    "tap ",
    "tun",
    "vpn",
    "npcap",
    "docker",
    "wsl",
    "zerotier",
    "tailscale",
    "openvpn",
    "wireguard",
];

/// 判断描述是否像虚拟网卡。
pub fn looks_virtual(description: &str, if_type: u32) -> bool {
    // IF_TYPE_SOFTWARE_LOOPBACK = 24
    if if_type == 24 {
        return true;
    }
    let lower = description.to_ascii_lowercase();
    VIRTUAL_HINTS.iter().any(|h| lower.contains(h))
}

#[cfg(windows)]
mod platform {
    use super::{looks_virtual, AdapterInfo};
    use portguard_core::error::{AppError, Result};
    use portguard_core::model::Ip;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

    /// `ERROR_BUFFER_OVERFLOW`
    const ERROR_BUFFER_OVERFLOW: u32 = 111;

    /// 枚举全部 IPv4 网卡地址。`include_virtual` 为 false 时过滤虚拟网卡。
    pub fn enumerate(include_virtual: bool) -> Result<Vec<AdapterInfo>> {
        let mut size: u32 = 16 * 1024;
        let mut buf: Vec<u8> = Vec::new();

        // GetAdaptersAddresses 是两段式调用：先用小缓冲试探，溢出后按需扩容。
        for _ in 0..4 {
            buf.resize(size as usize, 0);
            let addr = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
            let flags = GAA_FLAG_INCLUDE_PREFIX
                | GAA_FLAG_SKIP_ANYCAST
                | GAA_FLAG_SKIP_MULTICAST
                | GAA_FLAG_SKIP_DNS_SERVER;
            let ret = unsafe {
                GetAdaptersAddresses(
                    AF_INET.0 as u32,
                    flags,
                    None,
                    Some(addr),
                    &mut size,
                )
            };
            if ret == 0 {
                return Ok(unsafe { collect(addr, include_virtual) });
            }
            if ret != ERROR_BUFFER_OVERFLOW {
                return Err(AppError::WindowsApi {
                    api: "GetAdaptersAddresses",
                    code: ret,
                });
            }
            // size 已被写回所需大小，循环重试。
        }
        Err(AppError::WindowsApi {
            api: "GetAdaptersAddresses",
            code: ERROR_BUFFER_OVERFLOW,
        })
    }

    /// 遍历适配器链表。
    ///
    /// 安全前提：`head` 指向 `GetAdaptersAddresses` 填充的连续缓冲区，
    /// 且该缓冲区在整个遍历期间保持有效（由调用方保证）。
    unsafe fn collect(head: *mut IP_ADAPTER_ADDRESSES_LH, include_virtual: bool) -> Vec<AdapterInfo> {
        let mut out = Vec::new();
        let mut cur = head;
        while !cur.is_null() {
            let a = &*cur;
            let description = a.Description.to_string().unwrap_or_default();
            let friendly_name = a.FriendlyName.to_string().unwrap_or_default();
            let is_virtual = looks_virtual(&description, a.IfType);
            let is_up = a.OperStatus == IfOperStatusUp;
            let if_index = a.Anonymous1.Anonymous.IfIndex;

            let mut uni = a.FirstUnicastAddress;
            while !uni.is_null() {
                let u = &*uni;
                let sa = u.Address.lpSockaddr;
                if !sa.is_null() {
                    let sin = &*(sa as *const SOCKADDR_IN);
                    if sin.sin_family == AF_INET {
                        // S_addr 为网络字节序，转成主机序后交给 Ipv4Addr。
                        let raw = u32::from_be(sin.sin_addr.S_un.S_addr);
                        let ip = Ip::from(raw);
                        let prefix_len = u.OnLinkPrefixLength;
                        let info = AdapterInfo {
                            ip,
                            prefix_len,
                            mask: AdapterInfo::mask_from_prefix(prefix_len),
                            description: description.clone(),
                            friendly_name: friendly_name.clone(),
                            is_virtual,
                            is_up,
                            if_index,
                        };
                        if info.is_usable() && (include_virtual || !is_virtual) {
                            out.push(info);
                        }
                    }
                }
                uni = u.Next;
            }
            cur = a.Next;
        }
        // 排序保证 UI 每次显示顺序稳定。
        out.sort_by(|a, b| {
            a.ip.cmp(&b.ip)
                .then_with(|| a.description.cmp(&b.description))
        });
        out
    }
}

#[cfg(not(windows))]
mod platform {
    use super::AdapterInfo;
    use portguard_core::error::Result;

    /// 非 Windows 平台返回空列表，保证 `cargo test` 可跨平台执行。
    pub fn enumerate(_include_virtual: bool) -> Result<Vec<AdapterInfo>> {
        Ok(Vec::new())
    }
}

/// 枚举网卡。
pub fn enumerate(include_virtual: bool) -> Result<Vec<AdapterInfo>> {
    platform::enumerate(include_virtual)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 掩码换算正确() {
        assert_eq!(AdapterInfo::mask_from_prefix(24), "255.255.255.0");
        assert_eq!(AdapterInfo::mask_from_prefix(8), "255.0.0.0");
        assert_eq!(AdapterInfo::mask_from_prefix(32), "255.255.255.255");
        assert_eq!(AdapterInfo::mask_from_prefix(0), "0.0.0.0");
        assert_eq!(AdapterInfo::mask_from_prefix(16), "255.255.0.0");
        // 越界前缀做兜底，不 panic
        assert_eq!(AdapterInfo::mask_from_prefix(99), "255.255.255.255");
    }

    #[test]
    fn 虚拟网卡识别() {
        assert!(looks_virtual("VMware Virtual Ethernet Adapter for VMnet8", 6));
        assert!(looks_virtual("Hyper-V Virtual Ethernet Adapter", 6));
        assert!(looks_virtual("VirtualBox Host-Only Ethernet Adapter", 6));
        assert!(looks_virtual("Software Loopback Interface 1", 24));
        assert!(looks_virtual("TAP-Windows Adapter V9", 6));
        assert!(!looks_virtual(
            "Intel(R) Ethernet Connection I219-LM",
            6
        ));
        assert!(!looks_virtual("Realtek PCIe GbE Family Controller", 6));
    }

    #[test]
    fn 不可用地址被过滤() {
        let mk = |s: &str| AdapterInfo {
            ip: s.parse().unwrap(),
            prefix_len: 24,
            mask: "255.255.255.0".into(),
            description: "test".into(),
            friendly_name: "test".into(),
            is_virtual: false,
            is_up: true,
            if_index: 1,
        };
        assert!(!mk("0.0.0.0").is_usable());
        assert!(!mk("127.0.0.1").is_usable());
        assert!(mk("192.168.1.10").is_usable());
    }

    #[test]
    fn 展示文案包含地址与描述() {
        let a = AdapterInfo {
            ip: "192.168.1.10".parse().unwrap(),
            prefix_len: 24,
            mask: "255.255.255.0".into(),
            description: "Intel(R) Ethernet".into(),
            friendly_name: "本地连接".into(),
            is_virtual: false,
            is_up: true,
            if_index: 3,
        };
        assert_eq!(a.display(), "[192.168.1.10] Intel(R) Ethernet");
    }
}
