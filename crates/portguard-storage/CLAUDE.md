# portguard-storage 模块规范

## 职责
- 本地持久化层：`config.toml` 读写、`state/bans.json` 读写、日志落盘、运行期路径解析。
- 首次运行生成带注释的配置模板；配置损坏时备份而非静默覆盖。
- 不含任何网络与防火墙逻辑，便于纯单元测试。
- 不负责：配置语义与校验规则的定义（`Config::validate` / `normalize` 在 portguard-core）、抓包与判定。

## 对外接口
- `struct AppPaths`：`resolve` / `with_root` / `root` / `config_file` / `bans_file` / `state_dir` / `log_file` / `log_dir` / `data_dir` / `ensure`。
- `struct ConfigStore`：`new` / `path` / `load_or_create`（返回 `(Config, LoadOutcome)`）/ `save`。
- `enum LoadOutcome`：`Existing` / `CreatedDefault` / `RecoveredFromBroken(PathBuf)`；附 `is_recovery` / `describe`。
- `struct BanStore`：字段 `version` / `saved_at_ms` / `bans`；`new` / `load` / `save`。
- `struct Logger`：`start` / `log` / `info` / `warn` / `error` / `debug` / `tail` / `buffered_lines` / `dropped_lines` / `set_level` / `level` / `file` / `stop`（`Drop` 自动 `stop`）。

## 关键约束
- 落盘原子性：`BanStore::save`、`ConfigStore::save`（内部统一走 `write_atomic`）一律「写 `*.tmp` → `std::fs::rename` 覆盖」；禁止直接截断写目标文件，保证进程被强杀也不留半截文件，且不残留 `.tmp`。
- 路径解析：全部路径相对 exe 所在目录（`AppPaths::resolve`），保证绿色部署；取不到 exe 时回退当前工作目录，绝不 panic。
- 配置版本与兼容：`BanStore.version`（serde `default = 1`）+ 各字段 `#[serde(default)]`，保证旧/新结构可解析；写入前调用 core 的 `Config::normalize` 与 `validate`，校验不过拒绝写盘。当前仅记录版本号，无跨版本迁移函数。
- 损坏不静默丢弃：`config.toml` 解析失败先备份为 `config.toml.broken-<毫秒>` 再回退默认，并通过 `LoadOutcome::RecoveredFromBroken` 上报；`bans.json` 损坏直接返回 `AppError::Storage`，绝不当作空列表。
- 日志不阻塞业务线程：`log()` 只写内存环形缓冲 + `try_send`；通道（容量 4096）满时丢弃文件副本、保留内存副本并计入 `dropped_lines`；落盘由后台线程批量进行，超过 `MAX_LOG_BYTES`（16 MiB）滚动为 `.1`。
- 非测试代码禁止 `unwrap` / `expect`：`#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]`。
- `load_or_create` 不因文件损坏返回 `Err`（程序必须能启动）；但模板/配置写盘失败属真实故障，返回 `Err`。

## 测试
- 位置：各源文件内 `#[cfg(test)] mod tests`。
- 关键用例：`保存后加载结果一致`、`损坏文件报错而非静默丢弃`、`保存后不残留临时文件`、`缺少可选字段也能解析`、`首次运行生成模板且可再次加载`、`损坏配置被备份而非丢弃`、`非法配置拒绝保存`、`保存时自动规范化`、`日志能落盘并可按行读取`、`内存缓冲遵守容量上限`、`路径拼接正确`。
- 测试数量：19 个 `#[test]`（`bans.rs` 6 + `config_store.rs` 5 + `logger.rs` 5 + `paths.rs` 3）。

## 依赖关系
- 依赖：`portguard-core`（`error::{AppError, Result}`、`time::now_ms`、`config::Config`、`model::BanRecord`、`logging::{Level, LogBuffer, LogLine}`）。
- 被依赖：`portguard-app`、`portguard-web`。
