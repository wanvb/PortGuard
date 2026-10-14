@echo off
rem ============================================================
rem  PortGuard 一键编译脚本
rem  工具链：Rust 1.77.2（由 rust-toolchain.toml 自动锁定）
rem  目标：x86_64-pc-windows-msvc（Windows 7 SP1 及以上）
rem  用法：双击本文件，或在项目根目录执行 build.bat
rem ============================================================
setlocal
cd /d "%~dp0"
title PortGuard 一键编译脚本
color 0a

set "EXE=target\release\PortGuard.exe"
set "DB=ip2region_v4.xdb"

where cargo >nul 2>nul
if errorlevel 1 (
    echo.
    echo  [错误] 未找到 cargo，请先安装 Rust 1.77.2 工具链：https://rustup.rs
    echo.
    pause
    exit /b 1
)

:MENU
cls
echo.
echo  ============================================================
echo    PortGuard 一键编译脚本
echo  ============================================================
echo     [1] Release 编译（默认，Win7 兼容）
echo     [2] Release 编译 - 静态 CRT（目标机缺 VC++ 运行库时用）
echo     [3] Debug 编译
echo     [4] 编译并以管理员身份运行
echo     [5] 运行全部测试
echo     [6] clippy 静态检查
echo     [7] 代码格式检查
echo     [8] 打包 dist 目录（exe + 地理位置库）
echo     [9] 清理构建产物
echo     [10] 查看工具链与版本信息
echo     [0] 退出
echo  ============================================================
echo.
set "id="
set /p id=请输入选项后回车:
if not defined id goto EOF_INPUT
if "%id%"=="1" goto BUILD_RELEASE
if "%id%"=="2" goto BUILD_STATIC
if "%id%"=="3" goto BUILD_DEBUG
if "%id%"=="4" goto RUN_ELEVATED
if "%id%"=="5" goto TEST_ALL
if "%id%"=="6" goto CLIPPY
if "%id%"=="7" goto FMT_CHECK
if "%id%"=="8" goto PACK
if "%id%"=="9" goto CLEAN
if "%id%"=="10" goto INFO
if "%id%"=="0" goto END
echo.
echo  [提示] 无效选项：%id%
ping -n 2 127.0.0.1 >nul
goto MENU

:BUILD_RELEASE
echo.
echo  [编译] Release 模式，产物为单个 PortGuard.exe
echo.
cargo build --release
if errorlevel 1 goto FAIL
call :SHOW_EXE
goto PAUSE_MENU

:BUILD_STATIC
echo.
echo  [编译] Release + 静态 CRT（目标机没有 VC++ 运行库时使用）
echo  [注意] 该模式尚未在 Win7 真机验证，部署前请先确认能启动
echo.
set "RUSTFLAGS=-C target-feature=+crt-static"
cargo build --release
set "RUSTFLAGS="
if errorlevel 1 goto FAIL
call :SHOW_EXE
goto PAUSE_MENU

:BUILD_DEBUG
echo.
echo  [编译] Debug 模式（体积大、带调试信息，仅用于排查）
echo.
cargo build
if errorlevel 1 goto FAIL
echo.
echo  [完成] 产物：%cd%\target\debug\PortGuard.exe
goto PAUSE_MENU

:RUN_ELEVATED
if not exist "%EXE%" (
    echo.
    echo  [提示] 尚无 Release 产物，先编译
    echo.
    cargo build --release
    if errorlevel 1 goto FAIL
)
echo.
echo  [运行] 以管理员身份启动（抓包与防火墙封停需要提升权限）
echo         面板地址：http://127.0.0.1:58080
echo.
powershell -NoProfile -Command "Start-Process -FilePath '%EXE%' -Verb RunAs"
if errorlevel 1 echo  [错误] 提权启动失败，请手动右键 PortGuard.exe 以管理员身份运行
goto PAUSE_MENU

:TEST_ALL
echo.
echo  [测试] cargo test --workspace
echo.
cargo test --workspace
if errorlevel 1 goto FAIL
goto PAUSE_MENU

:CLIPPY
echo.
echo  [检查] cargo clippy --workspace --all-targets
echo.
cargo clippy --workspace --all-targets
if errorlevel 1 goto FAIL
goto PAUSE_MENU

:FMT_CHECK
echo.
echo  [检查] cargo fmt --all --check
echo.
cargo fmt --all --check
if errorlevel 1 echo  [提示] 存在格式差异，自动修复请执行：cargo fmt --all
goto PAUSE_MENU

:PACK
echo.
echo  [打包] 编译并生成发布目录 dist
echo.
cargo build --release
if errorlevel 1 goto FAIL
if not exist "dist" mkdir "dist"
if not exist "dist\data" mkdir "dist\data"
copy /y "%EXE%" "dist\PortGuard.exe" >nul
if exist "%DB%" (
    copy /y "%DB%" "dist\data\%DB%" >nul
    echo  [完成] 已复制地理位置库到 dist\data\
) else (
    echo  [提示] 未找到 %DB%，发布目录不含地理位置库（面板显示"未知"，不影响封停）
)
echo.
echo  [完成] 发布目录：%cd%\dist
echo.
echo  部署步骤：
echo     1. 把整个 dist 目录拷到服务器任意位置（绿色部署，无需安装）
echo     2. 右键 dist\PortGuard.exe，以管理员身份运行
echo     3. 浏览器打开面板：http://127.0.0.1:58080
echo     4. config.toml、state、logs 首次运行自动生成
echo.
echo  注意：Windows 7 / 2008 R2 / 2012 若提示缺少 DLL，
echo        请安装 VC++ 2015-2022 运行库，或用菜单 [2] 重新编译
goto PAUSE_MENU

:CLEAN
echo.
echo  [清理] cargo clean
echo.
cargo clean
echo.
echo  [完成] 构建产物已清理
goto PAUSE_MENU

:INFO
echo.
echo  [信息] 工具链版本
echo.
rustc -V
cargo -V
echo.
echo  [信息] 已安装工具链与目标
echo.
rustup show
if exist "%EXE%" call :SHOW_EXE
goto PAUSE_MENU

:EOF_INPUT
echo.
echo  [提示] 输入已结束，退出脚本
goto END

:FAIL
echo.
echo  ============================================================
echo    [失败] 上一条命令返回非零退出码，请查看上方错误输出
echo  ============================================================
goto PAUSE_MENU

:SHOW_EXE
if not exist "%EXE%" goto :EOF
for %%A in ("%EXE%") do echo  [完成] 产物：%%~fA（%%~zA 字节）
goto :EOF

:PAUSE_MENU
echo.
pause
goto MENU

:END
endlocal
exit /b 0
