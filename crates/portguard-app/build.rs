// 构建脚本：向主程序注入 Windows 应用程序清单（manifest）与程序图标资源
//
// 目的：
// 1. 让双击 PortGuard.exe 时默认弹出 UAC 提权对话框（requireAdministrator），
//    避免用户忘记「以管理员身份运行」导致抓包 / 防火墙操作权限不足。
// 2. 把 tray.ico 作为 RT_GROUP_ICON 资源写进 exe，使程序自身在资源管理器、
//    任务管理器、控制台窗口标题栏都显示图标（此前只有托盘区有图标）。
//
// 实现说明：
// - 仅对 MSVC 目标生效，链接器参数由 cargo:rustc-link-arg-bins 下发，
//   不受用户 RUSTFLAGS 环境变量覆盖（build.bat 的静态 CRT 构建会设置 RUSTFLAGS）。
// - /MANIFEST:EMBED 让链接器把清单作为 RT_MANIFEST 资源写入 exe，而非生成外部 .manifest 文件。
// - /MANIFESTUAC 指定请求的执行级别为 requireAdministrator。
// - 图标走 rc.exe：link.exe 只能接收二进制资源（.res），故先用 rc.exe 编译 .rc。
//   找不到 rc.exe 时只告警不中断，保证在老工具链上仍能编译出可用的 exe。

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // 仅在 Windows 目标下注入，避免影响其他平台的构建
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }

    // 仅针对 MSVC 工具链（GNU 工具链的链接器不识别这些参数，图标需改用 windres）
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_env != "msvc" {
        return;
    }

    // 把清单嵌入 exe，而不是生成同目录的 .manifest 附加文件
    println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
    // 默认请求管理员权限：用户双击运行即触发 UAC 提权
    println!("cargo:rustc-link-arg-bins=/MANIFESTUAC:level='requireAdministrator'");

    embed_icon();
}

/// 把托盘图标作为 exe 自身图标嵌入。
fn embed_icon() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    // 与托盘区共用同一份 ico，保证两处图标完全一致
    let icon = manifest_dir
        .join("..")
        .join("portguard-win")
        .join("assets")
        .join("tray.ico");
    if !icon.is_file() {
        println!(
            "cargo:warning=未找到图标文件 {}，本次构建的 exe 不带图标",
            icon.display()
        );
        return;
    }
    // 图标变化后重新执行本脚本
    println!("cargo:rerun-if-changed={}", icon.display());

    let out_dir = match std::env::var("OUT_DIR") {
        Ok(v) => PathBuf::from(v),
        Err(_) => return,
    };

    let Some(rc) = find_rc() else {
        println!(
            "cargo:warning=未找到 rc.exe（Windows SDK 资源编译器），本次构建的 exe 不带图标；\
             可设置环境变量 RC 指定其路径"
        );
        return;
    };

    // rc.exe 对含反斜杠 / 冒号的路径有转义歧义，故把 ico 复制到 OUT_DIR 用纯文件名引用
    let dist_icon = out_dir.join("portguard.ico");
    if std::fs::copy(&icon, dist_icon).is_err() {
        println!("cargo:warning=图标复制到构建目录失败，本次构建的 exe 不带图标");
        return;
    }

    let rc_file = out_dir.join("portguard.rc");
    // 资源 ID 用 1：资源管理器取编号最小的 RT_GROUP_ICON 作为 exe 图标
    let rc_text = "1 ICON \"portguard.ico\"\n";
    if std::fs::write(&rc_file, rc_text).is_err() {
        println!(
            "cargo:warning=写入 {} 失败，本次构建的 exe 不带图标",
            rc_file.display()
        );
        return;
    }

    let res_file = out_dir.join("portguard.res");
    let result = Command::new(rc)
        .current_dir(&out_dir)
        .arg("/nologo")
        .arg("/fo")
        .arg(&res_file)
        .arg(&rc_file)
        .output();

    match result {
        Ok(out) if out.status.success() && res_file.is_file() => {
            println!("cargo:rustc-link-arg-bins={}", res_file.display());
        }
        Ok(out) => println!(
            "cargo:warning=rc.exe 编译图标资源失败（退出码 {}）：{}，本次构建的 exe 不带图标",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => println!("cargo:warning=调用 rc.exe 失败：{e}，本次构建的 exe 不带图标"),
    }
}

/// 定位 Windows SDK 的 rc.exe，按目标架构挑选（资源对象的机器类型必须与目标一致）。
fn find_rc() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("RC") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }

    let arch = match std::env::var("CARGO_CFG_TARGET_ARCH")
        .unwrap_or_default()
        .as_str()
    {
        "x86" => "x86",
        "aarch64" => "arm64",
        _ => "x64",
    };

    for base in sdk_bin_roots() {
        // 形如 Windows Kits\10\bin\10.0.26100.0\<arch>\rc.exe，取版本号最大的一个
        let mut versions: Vec<PathBuf> = match std::fs::read_dir(&base) {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect(),
            Err(_) => continue,
        };
        versions.sort();
        for v in versions.iter().rev() {
            let candidate = v.join(arch).join("rc.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// 收集可能的 Windows SDK bin 根目录（不含版本号层）。
fn sdk_bin_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let env_keys = ["ProgramFiles(x86)", "ProgramFiles"];
    for key in env_keys {
        if let Ok(pf) = std::env::var(key) {
            let kits = Path::new(&pf).join("Windows Kits").join("10").join("bin");
            if kits.is_dir() {
                roots.push(kits);
            }
        }
    }
    roots
}
