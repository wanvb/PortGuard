// 构建脚本：向主程序注入 Windows 应用程序清单（manifest）
//
// 目的：让双击 PortGuard.exe 时默认弹出 UAC 提权对话框（requireAdministrator），
// 避免用户忘记「以管理员身份运行」导致抓包 / 防火墙操作权限不足。
//
// 实现说明：
// - 仅对 MSVC 目标生效，链接器参数由 cargo:rustc-link-arg-bins 下发，
//   不受用户 RUSTFLAGS 环境变量覆盖（build.bat 的静态 CRT 构建会设置 RUSTFLAGS）。
// - /MANIFEST:EMBED 让链接器把清单作为 RT_MANIFEST 资源写入 exe，而非生成外部 .manifest 文件。
// - /MANIFESTUAC 指定请求的执行级别为 requireAdministrator。

fn main() {
    // 仅在 Windows 目标下注入，避免影响其他平台的构建
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }

    // 仅针对 MSVC 工具链（GNU 工具链的链接器不识别这些参数）
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_env != "msvc" {
        return;
    }

    // 把清单嵌入 exe，而不是生成同目录的 .manifest 附加文件
    println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
    // 默认请求管理员权限：用户双击运行即触发 UAC 提权
    println!("cargo:rustc-link-arg-bins=/MANIFESTUAC:level='requireAdministrator'");
}
