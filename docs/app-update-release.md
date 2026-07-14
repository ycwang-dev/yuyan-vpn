# 雨燕 SwiftVPN 应用内更新发布

## 架构

- `ycwang-dev/yuyan-vpn`：私有源码与 GitHub Actions，不向客户端暴露访问令牌。
- `ycwang-dev/yuyan-vpn-releases`：公开资产仓库，只保存 DMG、Tauri updater 包、签名和 `latest.json`。
- App 使用内置公钥验证更新签名；签名不通过时不会安装。
- 当前正式更新只覆盖 macOS ARM64 与 Intel。Windows 双 VPN backend 通过真机门禁前，不进入公开 Release 或 updater manifest。

## 首次启用

1. 创建公开仓库 `ycwang-dev/yuyan-vpn-releases`，初始化 `main` 分支。
2. 创建仅能写入该公开资产仓库的 fine-grained personal access token，授予 `Contents: Read and write`。
3. 在私有源码仓库的 Actions secrets 中配置：
   - `PUBLIC_RELEASE_TOKEN`：上一步生成的细粒度令牌。
   - `TAURI_SIGNING_PRIVATE_KEY`：本机 `~/.tauri/yuyan-vpn-updater.key` 的完整内容。
   - `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`：当前密钥为空密码，可不创建或保持为空。
4. 将 `~/.tauri/yuyan-vpn-updater.key` 离线备份到受控密码库。该私钥丢失后，已安装旧版本将无法验证新密钥签出的更新。
5. 在 GitHub `Billing & plans` 中修复失败的付款方式，并为 Actions 设置可用预算；计费门禁解除前 Release Job 无法启动。

## 发布产物

main 分支构建成功后，workflow 会发布：

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
