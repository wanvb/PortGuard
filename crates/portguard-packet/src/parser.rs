//! IPv4 / TCP / UDP 解析。
//!
//! 本模块**不依赖任何 Windows API**：输入一段字节，输出 [`PacketInfo`]，
//! 因此可以用构造数据做完整单元测试（规范 30.1）。
//!
//! 关键约束（规范 3.2）：
//! - 必须按 RFC 解析 IHL，**不得假定 IP 头永远是 20 字节**；
//! - TCP 必须解析 data offset，**不得假定 TCP 头永远是 20 字节**；
//! - 所有切片访问都必须做长度检查，任何畸形包只能返回错误，绝不 panic。

use portguard_core::error::{AppError, Result};
use portguard_core::model::{Ip, PacketInfo, Protocol, TcpFlags};

/// IPv4 最小头部长度。
const IPV4_MIN_HEADER: usize = 20;
/// TCP 最小头部长度。
const TCP_MIN_HEADER: usize = 20;
/// UDP 头部长度（固定）。
const UDP_HEADER: usize = 8;

/// 协议号。
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;

/// 以太网帧头中的 EtherType 位置与 IPv4 取值，用于自动跳过帧头。
const ETH_HEADER_LEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;

/// 解析结果。
#[derive(Clone, Copy, Debug)]
pub struct ParsedPacket {
    /// 通用包信息（时间戳由调用方回填）。
    pub info: PacketInfo,
    /// IP 头长度（字节）。
    pub ip_header_len: usize,
    /// 传输层头长度（字节）；UDP 固定 8，ICMP 为 4。
    pub transport_header_len: usize,
}

/// 解析一段原始字节。
///
/// 输入既可以是 `SIO_RCVALL` 直接给出的 IP 包，也可以是带以太网头的完整帧，
/// 本函数会自动识别并跳过帧头，便于用 Wireshark 导出的数据做回归测试。
pub fn parse_ethernet_or_ip(buf: &[u8]) -> Result<ParsedPacket> {
    if buf.is_empty() {
        return Err(AppError::PacketParse("空数据".into()));
    }
    let offset = detect_link_offset(buf);
    let ip = &buf[offset..];
    parse_ipv4(ip)
}

/// 判断是否带以太网头。
///
/// 判定依据：首字节高 4 位不是 4，但第 13-14 字节的 EtherType 是 0x0800，
/// 且跳过头之后确实是一个 IPv4 包。
fn detect_link_offset(buf: &[u8]) -> usize {
    let version = buf[0] >> 4;
    if version == 4 {
        return 0;
    }
    if buf.len() > ETH_HEADER_LEN
        && u16::from_be_bytes([buf[12], buf[13]]) == ETHERTYPE_IPV4
        && buf[ETH_HEADER_LEN] >> 4 == 4
    {
        return ETH_HEADER_LEN;
    }
    0
}

/// 解析 IPv4 包（输入必须以 IP 头开始）。
pub fn parse_ipv4(buf: &[u8]) -> Result<ParsedPacket> {
    if buf.len() < IPV4_MIN_HEADER {
        return Err(AppError::PacketParse(format!(
            "数据长度不足 IPv4 最小头部：{} 字节",
            buf.len()
        )));
    }

    let version = buf[0] >> 4;
    if version != 4 {
        return Err(AppError::PacketParse(format!(
            "非 IPv4 包（版本号 {}）",
            version
        )));
    }

    // IHL 以 4 字节为单位，必须按实际值取，不能假定 20。
    let ihl = ((buf[0] & 0x0F) as usize) * 4;
    if ihl < IPV4_MIN_HEADER {
        return Err(AppError::PacketParse(format!("IPv4 头长度非法：{}", ihl)));
    }
    if buf.len() < ihl {
        return Err(AppError::PacketParse(format!(
            "数据被截断：声明头长 {}，实际 {}",
            ihl,
            buf.len()
        )));
    }

    let total_length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    // 分片偏移非 0 的包不含完整传输层头，直接丢弃。
    let frag_offset = u16::from_be_bytes([buf[6], buf[7]]);
    if frag_offset & 0x1FFF != 0 {
        return Err(AppError::PacketParse("IP 分片包，跳过".into()));
    }

    let protocol = buf[9];
    let src = Ip::new(buf[12], buf[13], buf[14], buf[15]);
    let dst = Ip::new(buf[16], buf[17], buf[18], buf[19]);

    // 以 total_length 与实收长度中较小者作为有效载荷边界。
    let end = if total_length >= ihl && total_length <= buf.len() {
        total_length
    } else {
        buf.len()
    };
    let payload = &buf[ihl..end];

    let mut info = PacketInfo {
        src,
        dst,
        src_port: 0,
        dst_port: 0,
        protocol: Protocol::Icmp,
        tcp_flags: TcpFlags::default(),
        length: total_length.min(u16::MAX as usize) as u16,
        timestamp_ms: 0,
    };
    let transport_header_len;

    match protocol {
        IPPROTO_TCP => {
            if payload.len() < TCP_MIN_HEADER {
                return Err(AppError::PacketParse("TCP 头长度不足".into()));
            }
            let data_offset = ((payload[12] >> 4) as usize) * 4;
            if data_offset < TCP_MIN_HEADER || data_offset > payload.len() {
                return Err(AppError::PacketParse(format!(
                    "TCP 头长度非法：{}",
                    data_offset
                )));
            }
            info.src_port = u16::from_be_bytes([payload[0], payload[1]]);
            info.dst_port = u16::from_be_bytes([payload[2], payload[3]]);
            info.protocol = Protocol::Tcp;
            info.tcp_flags = decode_tcp_flags(payload[13]);
            transport_header_len = data_offset;
        }
        IPPROTO_UDP => {
            if payload.len() < UDP_HEADER {
                return Err(AppError::PacketParse("UDP 头长度不足".into()));
            }
            info.src_port = u16::from_be_bytes([payload[0], payload[1]]);
            info.dst_port = u16::from_be_bytes([payload[2], payload[3]]);
            info.protocol = Protocol::Udp;
            transport_header_len = UDP_HEADER;
        }
        IPPROTO_ICMP => {
            info.protocol = Protocol::Icmp;
            transport_header_len = 4;
        }
        other => {
            return Err(AppError::PacketParse(format!(
                "暂不支持的 IP 协议号：{}",
                other
            )))
        }
    }

    Ok(ParsedPacket {
        info,
        ip_header_len: ihl,
        transport_header_len,
    })
}

/// 解码 TCP 标志位字节。
#[inline]
pub fn decode_tcp_flags(byte: u8) -> TcpFlags {
    TcpFlags {
        fin: byte & 0x01 != 0,
        syn: byte & 0x02 != 0,
        rst: byte & 0x04 != 0,
        psh: byte & 0x08 != 0,
        ack: byte & 0x10 != 0,
        urg: byte & 0x20 != 0,
    }
}

/// 判断是否为 ICMPv4 Echo Request（type=8），用于「禁止 Ping」相关统计。
pub fn is_icmp_echo_request(buf: &[u8]) -> bool {
    let offset = detect_link_offset(buf);
    let ip = &buf[offset..];
    if ip.len() < IPV4_MIN_HEADER {
        return false;
    }
    let ihl = ((ip[0] & 0x0F) as usize) * 4;
    if ip[9] != IPPROTO_ICMP || ip.len() <= ihl {
        return false;
    }
    ip[ihl] == 8
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个 IPv4 + TCP 包。
    /// `ip_options` 用于制造非 20 字节的 IP 头，验证 IHL 解析。
    fn build_tcp(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        flags: u8,
        ip_options: usize,
        tcp_options: usize,
    ) -> Vec<u8> {
        let ihl = 20 + ip_options;
        let tcp_len = 20 + tcp_options;
        let total = ihl + tcp_len;
        let mut b = vec![0u8; total];

        b[0] = 0x40 | ((ihl / 4) as u8);
        b[1] = 0;
        b[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        b[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        b[6..8].copy_from_slice(&0u16.to_be_bytes());
        b[8] = 64;
        b[9] = IPPROTO_TCP;
        b[12..16].copy_from_slice(&src);
        b[16..20].copy_from_slice(&dst);

        let t = ihl;
        b[t..t + 2].copy_from_slice(&sport.to_be_bytes());
        b[t + 2..t + 4].copy_from_slice(&dport.to_be_bytes());
        b[t + 12] = ((tcp_len / 4) as u8) << 4;
        b[t + 13] = flags;
        b
    }

    /// 构造一个 IPv4 + UDP 包。
    fn build_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: usize) -> Vec<u8> {
        let total = 20 + 8 + payload;
        let mut b = vec![0u8; total];
        b[0] = 0x45;
        b[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        b[8] = 64;
        b[9] = IPPROTO_UDP;
        b[12..16].copy_from_slice(&src);
        b[16..20].copy_from_slice(&dst);
        b[20..22].copy_from_slice(&sport.to_be_bytes());
        b[22..24].copy_from_slice(&dport.to_be_bytes());
        b[24..26].copy_from_slice(&((8 + payload) as u16).to_be_bytes());
        b
    }

    fn build_icmp(src: [u8; 4], dst: [u8; 4], icmp_type: u8) -> Vec<u8> {
        let total = 20 + 8;
        let mut b = vec![0u8; total];
        b[0] = 0x45;
        b[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        b[8] = 64;
        b[9] = IPPROTO_ICMP;
        b[12..16].copy_from_slice(&src);
        b[16..20].copy_from_slice(&dst);
        b[20] = icmp_type;
        b
    }

    #[test]
    fn 解析标准连接请求() {
        let buf = build_tcp([192, 168, 1, 10], [203, 0, 113, 9], 44444, 3389, 0x02, 0, 0);
        let p = parse_ipv4(&buf).unwrap();
        assert_eq!(p.info.src.to_string(), "192.168.1.10");
        assert_eq!(p.info.dst.to_string(), "203.0.113.9");
        assert_eq!(p.info.src_port, 44444);
        assert_eq!(p.info.dst_port, 3389);
        assert_eq!(p.info.protocol, Protocol::Tcp);
        assert!(p.info.tcp_flags.syn);
        assert!(!p.info.tcp_flags.ack);
        assert!(p.info.tcp_flags.is_connection_request());
        assert_eq!(p.ip_header_len, 20);
        assert_eq!(p.transport_header_len, 20);
    }

    #[test]
    fn 解析握手响应() {
        let buf = build_tcp([203, 0, 113, 9], [192, 168, 1, 10], 3389, 44444, 0x12, 0, 0);
        let p = parse_ipv4(&buf).unwrap();
        assert!(p.info.tcp_flags.syn);
        assert!(p.info.tcp_flags.ack);
        assert!(
            !p.info.tcp_flags.is_connection_request(),
            "SYN+ACK 是服务端响应，不得当作新连接"
        );
    }

    #[test]
    fn 解析确认结束复位标志() {
        let ack = parse_ipv4(&build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1, 2, 0x10, 0, 0)).unwrap();
        assert!(ack.info.tcp_flags.ack && !ack.info.tcp_flags.syn);

        let fin = parse_ipv4(&build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1, 2, 0x11, 0, 0)).unwrap();
        assert!(fin.info.tcp_flags.fin && fin.info.tcp_flags.ack);

        let rst = parse_ipv4(&build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1, 2, 0x04, 0, 0)).unwrap();
        assert!(rst.info.tcp_flags.rst && rst.info.tcp_flags.is_reset());
    }

    #[test]
    fn 解析用户数据报() {
        let buf = build_udp([192, 168, 1, 10], [8, 8, 8, 8], 5353, 53, 12);
        let p = parse_ipv4(&buf).unwrap();
        assert_eq!(p.info.protocol, Protocol::Udp);
        assert_eq!(p.info.src_port, 5353);
        assert_eq!(p.info.dst_port, 53);
        assert_eq!(p.transport_header_len, 8);
        assert_eq!(p.info.length, 40);
    }

    #[test]
    fn 解析网际控制报文() {
        let buf = build_icmp([1, 1, 1, 1], [2, 2, 2, 2], 8);
        let p = parse_ipv4(&buf).unwrap();
        assert_eq!(p.info.protocol, Protocol::Icmp);
        assert!(is_icmp_echo_request(&buf));
        let reply = build_icmp([1, 1, 1, 1], [2, 2, 2, 2], 0);
        assert!(!is_icmp_echo_request(&reply));
    }

    #[test]
    fn 选项导致头长变化时按首部长度解析() {
        for opt in [0usize, 4, 8, 12, 36] {
            let buf = build_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 3389, 0x02, opt, 0);
            let p = parse_ipv4(&buf).unwrap();
            assert_eq!(p.ip_header_len, 20 + opt);
            assert_eq!(p.info.dst_port, 3389, "IP 选项={} 时端口解析错误", opt);
            assert_eq!(p.info.src_port, 1234);
        }
    }

    #[test]
    fn 传输层选项导致头长变化时按数据偏移解析() {
        for opt in [0usize, 4, 8, 20] {
            let buf = build_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 0x02, 0, opt);
            let p = parse_ipv4(&buf).unwrap();
            assert_eq!(p.transport_header_len, 20 + opt);
            assert_eq!(p.info.dst_port, 80);
        }
    }

    #[test]
    fn 解析带以太网头的帧() {
        let inner = build_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 445, 0x02, 0, 0);
        let mut frame = vec![0u8; 14];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame.extend_from_slice(&inner);
        let p = parse_ethernet_or_ip(&frame).unwrap();
        assert_eq!(p.info.dst_port, 445);
        assert_eq!(p.ip_header_len, 20);
    }

    #[test]
    fn 畸形包不会panic() {
        // 各种截断与非法值都必须返回错误而不是崩溃
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x45],
            vec![0x45; 10],
            vec![0x45; 19],
            {
                let mut v = vec![0u8; 20];
                v[0] = 0x44; // IHL = 16 < 20，非法
                v[9] = IPPROTO_TCP;
                v
            },
            {
                let mut v = vec![0u8; 20];
                v[0] = 0x4F; // IHL = 60，但实际只有 20 字节
                v[9] = IPPROTO_TCP;
                v
            },
            {
                let mut v = vec![0u8; 20];
                v[0] = 0x45;
                v[9] = IPPROTO_TCP; // 无传输层数据
                v
            },
            {
                let mut v = vec![0u8; 24];
                v[0] = 0x45;
                v[9] = IPPROTO_UDP; // 载荷仅 4 字节，不足 UDP 头
                v
            },
            {
                let mut v = vec![0u8; 40];
                v[0] = 0x45;
                v[9] = 47; // GRE，未支持
                v
            },
        ];
        for (i, c) in cases.iter().enumerate() {
            assert!(parse_ipv4(c).is_err(), "用例 {} 应当返回错误", i);
        }
    }

    #[test]
    fn 分片包被跳过() {
        let mut buf = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1, 2, 0x02, 0, 0);
        // 设置分片偏移为 1
        buf[6] = 0x00;
        buf[7] = 0x01;
        assert!(parse_ipv4(&buf).is_err());
    }

    #[test]
    fn 总长度小于头长时退化为实收长度() {
        let mut buf = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1234, 80, 0x02, 0, 0);
        // 故意声明一个比头长还小的总长度（畸形包）
        buf[2..4].copy_from_slice(&10u16.to_be_bytes());
        let p = parse_ipv4(&buf).unwrap();
        assert_eq!(p.info.dst_port, 80, "畸形总长度不应影响传输层解析");
    }

    #[test]
    fn 标志位解码全量覆盖() {
        assert_eq!(decode_tcp_flags(0x00).to_short_string(), "-");
        assert_eq!(decode_tcp_flags(0x02).to_short_string(), "S");
        assert_eq!(decode_tcp_flags(0x12).to_short_string(), "SA");
        assert_eq!(decode_tcp_flags(0x18).to_short_string(), "AP");
        assert_eq!(decode_tcp_flags(0x11).to_short_string(), "AF");
        assert_eq!(decode_tcp_flags(0x04).to_short_string(), "R");
        assert_eq!(decode_tcp_flags(0x3F).to_short_string(), "SAFRPU");
    }

    #[test]
    fn 非第四版协议被拒绝() {
        let mut buf = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1, 2, 0x02, 0, 0);
        buf[0] = 0x65; // 版本 6
        assert!(parse_ipv4(&buf).is_err());
    }
}
