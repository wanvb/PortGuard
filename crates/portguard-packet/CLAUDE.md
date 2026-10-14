# portguard-packet 模块规范

## 职责
- 负责网卡枚举（`GetAdaptersAddresses`）、raw socket 抓包（`SIO_RCVALL`）、IPv4 / TCP / UDP / TCP flags 解析，产出 `PacketInfo`（规范 3.2）。
- 只把字节变成 `PacketInfo`，绝不在本模块决定「封停谁」；判定全部交给 `portguard-core::engine`。
- 数据流：`raw socket → parser → PacketInfo → portguard-core 规则引擎`。
- 平台相关代码收敛在 `cfg(windows)` / `cfg(not(windows))` 的 `platform` 子模块内，业务层通过同名顶层函数转发。

## 对外接口
| 项 | 签名 / 说明 |
|------|------|
| `enumerate(include_virtual: bool) -> Result<Vec<AdapterInfo>>` | 枚举可用 IPv4 网卡，`include_virtual=false` 时过滤虚拟网卡 |
| `AdapterInfo` | 字段 `ip` / `prefix_len` / `mask` / `description` / `friendly_name` / `is_virtual` / `is_up` / `if_index`；方法 `display`、`is_usable`、`is_link_local`、`mask_from_prefix` |
| `looks_virtual(description: &str, if_type: u32) -> bool` | 按关键字与 `IF_TYPE_SOFTWARE_LOOPBACK`(24) 提示性分类虚拟网卡 |
| `start<P,E>(local_ip: Ip, on_packet: P, on_error: E) -> Result<CaptureHandle>` | 启动抓包；`Err` 表示监听未启动成功，调用方须如实展示 |
| `CaptureHandle` | `stop`、`is_running`、`local_ip`；`Drop` 时自动停止回收线程 |
| `parse_ethernet_or_ip(buf: &[u8]) -> Result<ParsedPacket>` | 自动识别并跳过以太网头后解析 IPv4 |
| `parse_ipv4(buf: &[u8]) -> Result<ParsedPacket>` | 解析以 IP 头开始的报文 |
| `ParsedPacket` | 字段 `info: PacketInfo` / `ip_header_len` / `transport_header_len` |
| `decode_tcp_flags(byte: u8) -> TcpFlags` | 解码 TCP 标志位字节 |
| `is_icmp_echo_request(buf: &[u8]) -> bool` | 判断 ICMPv4 Echo Request（type=8） |
| 顶层再导出 | `enumerate`、`AdapterInfo`、`CaptureHandle`、`parse_ethernet_or_ip`、`parse_ipv4`、`ParsedPacket` |

## 关键约束
- 不得在本模块直接决定封停对象（规范 3.2）。
- parser 必须按 RFC 解析 IHL 与 TCP data offset，不得假定 IP / TCP 头永远 20 字节；所有切片访问必须做长度检查，任何畸形包只能返回 `Err`，绝不 panic。
- 抓包链路严格保持原程序顺序：`WSAStartup → socket(AF_INET, SOCK_RAW, IPPROTO_IP) → bind(本机 IP) → WSAIoctl(SIO_RCVALL) → recv 循环`（规范 1.2），不得替换为未经验证的方案。
- 套接字创建、`bind`、`SIO_RCVALL` 全部在调用线程完成，权限不足 / 网卡不可用立即返回错误；仅阻塞的 `recv` 循环放入后台线程。
- `recv` 通过 `SO_RCVTIMEO`（500 ms）周期性醒来以响应停止请求；`WSAETIMEDOUT` / `WSAEINTR` 视为正常继续。
- 早期失败路径（socket / bind / setsockopt / WSAIoctl / 建线程）必须先 `closesocket` + `WSACleanup` 再返回，避免 Winsock 引用计数泄漏；线程退出前亦须 `closesocket` + `WSACleanup`。
- 虚拟网卡不默认排除，是否展示由配置项 `network.include_virtual` 决定（规范 12）；但必须排除 `0.0.0.0` 与回环地址（`is_usable`）。
- 只依赖 `portguard-core`；`windows` crate 仅在 `cfg(windows)` 下引入，非 Windows 平台 `enumerate` 返回空表、`start` 返回 `Err`，保证 `cargo test` 可跨平台编译。
- 畸形包 / 分片包 / 非 IPv4 包在 `recv` 循环中属常态，静默忽略，不作错误上报以免日志被噪声淹没。

## 测试
- 位置：各源文件内联 `#[cfg(test)] mod tests`。
- 分布：`adapter.rs` 5、`parser.rs` 13；`capture.rs`、`lib.rs` 无测试（依赖真实网卡与管理员权限）。
- 合计 `#[test]`：18 个。
- 关键用例：
  - `adapter`：掩码换算正确、虚拟网卡识别、不可用地址被过滤、自动私有地址被识别、展示文案包含地址与描述。
  - `parser`：解析标准连接请求、解析握手响应、选项导致头长变化时按首部长度解析、传输层选项导致头长变化时按数据偏移解析、解析带以太网头的帧、畸形包不会 panic、分片包被跳过、总长度小于头长时退化为实收长度、标志位解码全量覆盖。

## 依赖关系
- 本 crate 依赖：`portguard-core`；`cfg(windows)` 下依赖 `windows`（features 含 `Win32_NetworkManagement_IpHelper` / `Win32_NetworkManagement_Ndis` / `Win32_Networking_WinSock` / `Win32_System_IO`）。
- 被依赖：`portguard-app`（`src/main.rs`、`src/controller.rs`、`src/runtime.rs`）。
