# 雨燕 SwiftVPN 应用内更新发布

## 架构

- `ycwang-dev/yuyan-vpn`：公开源码、GitHub Actions 与安装包统一存放在同一仓库。
- App 匿名读取当前仓库 Releases 中的 `latest.json` 和更新资产，不向客户端下发访问令牌。
- App 使用内置公钥验证更新签名；签名不通过时不会安装。
- 当前正式更新只覆盖 macOS ARM64 与 Intel。Windows 双 VPN backend 通过真机门禁前，不进入公开 Release 或 updater manifest。

## 首次启用

1. 确认仓库 `ycwang-dev/yuyan-vpn` 保持 Public，并在 Actions workflow 中授予 `contents: write`。
2. 在当前仓库的 Actions secrets 中配置：
   - `TAURI_SIGNING_PRIVATE_KEY`：本机 `~/.tauri/yuyan-vpn-updater.key` 的完整内容。
   - `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`：当前密钥为空密码，可不创建或保持为空。
   - `PERSONAL_ACCESS_TOKEN`：仅在安装 `@ycwang-dev/*` 私有 npm 包时使用，需要 `read:packages` 权限，不参与 Release 发布。
   - `VITE_DEFAULT_FORTINET_HOST`、`VITE_DEFAULT_FORTINET_PORT`、`VITE_DEFAULT_FORTINET_USERNAME`：正式 Fortinet 网关、端口和共享账号。
   - `VITE_DEFAULT_FORTINET_ROUTES`：逗号分隔的北京内网 CIDR 列表。
   - `VITE_DEFAULT_ATRUST_HOST`、`VITE_DEFAULT_ATRUST_PORT`、`VITE_DEFAULT_ATRUST_USERNAME`：正式 aTrust 网关、端口和共享账号。
3. 将 `~/.tauri/yuyan-vpn-updater.key` 离线备份到受控密码库。该私钥丢失后，已安装旧版本将无法验证新密钥签出的更新。

本地 `.env.local` 已被 `*.local` 忽略规则排除，不应提交。本机 Tauri 构建会读取其中同名的 `VITE_DEFAULT_*` 参数；GitHub Actions 无法读取开发机文件，正式 CI 必须配置上述 Actions secrets。缺失参数或网关仍为 `example.com` 时，workflow 会在打包前终止，避免发布无效安装包。

## 发布产物

main 分支构建成功后，workflow 使用当前仓库自动提供的 `GITHUB_TOKEN` 创建 Release，并发布：

- `*.dmg`：用户首次安装或手工恢复使用。
- `yuyan-vpn_<version>_darwin-aarch64.app.tar.gz` 与 `.sig`。
- `yuyan-vpn_<version>_darwin-x86_64.app.tar.gz` 与 `.sig`。
- `latest.json`：包含版本、发布时间、双架构下载地址和内嵌签名。

功能分支仍可生成 prerelease；只有 main 的 stable Release 会被 `releases/latest/download/latest.json` 返回。

## 客户端流程

1. 启动 2 秒后检查更新，之后每 6 小时静默检查。
2. 发现更新后后台下载，并在胶囊显示进度、速度和预计剩余时间。
3. 下载完成后由 Tauri updater 使用内置公钥验证签名。
4. 用户点击“重启更新”后，App 先安全断开双 VPN 并清理网络资源。
5. 清理成功才安装并重启；清理或安装失败时保留当前 App，并恢复 VPN 连接门禁。

Tauri 2 官方 updater 当前不提供跨进程断点续传。本版本不再展示无法兑现的暂停按钮；网络失败后可点击胶囊重新下载。
