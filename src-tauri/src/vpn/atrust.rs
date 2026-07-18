#[cfg(target_os = "macos")]
use super::resolve_macos_sidecar;
use super::{
    atrust_client_data_path, emit_atrust_auth_feedback, emit_vpn_log, extract_atrust_server_error,
    is_atrust_captcha_error, is_atrust_credential_error, load_vpn_config,
    should_report_atrust_server_error, validate_vpn_connection_config, VpnCaptchaPayload,
    VpnManager, VpnManagerInner, VpnStatePayload, VpnStatus, VpnType,
};
#[cfg(target_os = "macos")]
use super::{classify_atrust_client_data, AtrustClientDataState, MAX_ATRUST_CLIENT_DATA_BYTES};
use std::process::Stdio;
use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use tokio::io::AsyncWriteExt;
#[cfg(target_os = "macos")]
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Mutex;

/// 将用户输入编码为 TOML 基本字符串内容，防止引号或换行破坏运行时配置。
fn toml_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/** macOS 启动前得到的 aTrust 客户端登录态检查结果。 */
#[cfg(target_os = "macos")]
struct PreparedAtrustClientData {
    state: AtrustClientDataState,
    reset_invalid: bool,
}

/**
 * 创建或校验 macOS aTrust 客户端数据文件，并在交给 root 子进程前收紧权限。
 */
#[cfg(target_os = "macos")]
fn prepare_atrust_client_data(path: &std::path::Path) -> Result<PreparedAtrustClientData, String> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let directory = path
        .parent()
        .ok_or_else(|| "aTrust 登录状态路径缺少父目录".to_string())?;
    match std::fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err("aTrust 登录状态目录不是安全的普通目录".to_string());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(directory)
                .map_err(|error| format!("创建 aTrust 登录状态目录失败: {error}"))?;
        }
        Err(error) => return Err(format!("检查 aTrust 登录状态目录失败: {error}")),
    }
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("收紧 aTrust 登录状态目录权限失败: {error}"))?;

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("检查 aTrust 登录状态文件失败: {error}")),
    };
    let Some(metadata) = metadata else {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| format!("创建 aTrust 登录状态文件失败: {error}"))?;
        file.write_all(b"{}")
            .map_err(|error| format!("初始化 aTrust 登录状态文件失败: {error}"))?;
        return Ok(PreparedAtrustClientData {
            state: AtrustClientDataState::Empty,
            reset_invalid: false,
        });
    };

    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() > 1 {
        return Err("aTrust 登录状态文件不是安全的独立普通文件".to_string());
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("收紧 aTrust 登录状态文件权限失败: {error}"))?;
    if metadata.len() <= MAX_ATRUST_CLIENT_DATA_BYTES {
        let content = std::fs::read(path)
            .map_err(|error| format!("读取 aTrust 登录状态文件失败: {error}"))?;
        if let Some(state) = classify_atrust_client_data(&content) {
            return Ok(PreparedAtrustClientData {
                state,
                reset_invalid: false,
            });
        }
    }

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|error| format!("重置损坏的 aTrust 登录状态文件失败: {error}"))?;
    file.write_all(b"{}")
        .map_err(|error| format!("初始化 aTrust 登录状态文件失败: {error}"))?;
    Ok(PreparedAtrustClientData {
        state: AtrustClientDataState::Empty,
        reset_invalid: true,
    })
}

/**
 * 把旧版本由 root 创建的固定客户端数据文件迁回应用用户，随后再由普通进程收紧权限。
 *
 * 仅允许处理 Tauri 应用数据目录内、属主为 root 的独立普通文件；`chown -h` 不跟随符号链接。
 */
#[cfg(target_os = "macos")]
async fn repair_legacy_atrust_client_data_owner(
    path: &std::path::Path,
    sudo_password: &str,
) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("检查旧版 aTrust 登录状态属主失败: {error}")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() > 1 {
        return Err("旧版 aTrust 登录状态不是安全的独立普通文件".to_string());
    }

    let app_data_directory = path
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or_else(|| "aTrust 登录状态路径缺少应用数据目录".to_string())?;
    let app_metadata = std::fs::symlink_metadata(app_data_directory)
        .map_err(|error| format!("检查 aTrust 应用数据目录失败: {error}"))?;
    if app_metadata.file_type().is_symlink() || !app_metadata.is_dir() {
        return Err("aTrust 应用数据目录不是安全的普通目录".to_string());
    }

    let target_uid = app_metadata.uid();
    let target_gid = app_metadata.gid();
    if metadata.uid() == target_uid {
        return Ok(false);
    }
    if metadata.uid() != 0 {
        return Err(format!(
            "aTrust 登录状态属于未知用户 UID {}，已拒绝自动接管",
            metadata.uid()
        ));
    }

    let owner = format!("{target_uid}:{target_gid}");
    let mut child = tokio::process::Command::new("sudo")
        .arg("-S")
        .arg("-p")
        .arg("")
        .arg("/usr/sbin/chown")
        .arg("-h")
        .arg(owner)
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("启动旧版 aTrust 登录状态迁移失败: {error}"))?;
    let Some(mut stdin) = child.stdin.take() else {
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Err("无法打开 aTrust 登录状态迁移授权管道".to_string());
    };
    if let Err(error) = stdin
        .write_all(format!("{sudo_password}\n").as_bytes())
        .await
    {
        drop(stdin);
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Err(format!("提交 aTrust 登录状态迁移授权失败: {error}"));
    }
    drop(stdin);
    let status = child
        .wait()
        .await
        .map_err(|error| format!("等待 aTrust 登录状态迁移失败: {error}"))?;
    if !status.success() {
        return Err("修复旧版 aTrust 登录状态文件属主失败".to_string());
    }

    let repaired_metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("复核 aTrust 登录状态迁移结果失败: {error}"))?;
    if repaired_metadata.file_type().is_symlink()
        || !repaired_metadata.is_file()
        || repaired_metadata.nlink() > 1
        || repaired_metadata.uid() != target_uid
    {
        return Err("aTrust 登录状态迁移结果不安全，已停止连接".to_string());
    }
    Ok(true)
}

/** 生成不包含 Cookie、设备 ID 或本地路径的登录态复用日志。 */
#[cfg(target_os = "macos")]
fn atrust_client_data_log(prepared: &PreparedAtrustClientData) -> &'static str {
    if prepared.reset_invalid {
        return "检测到损坏的 aTrust 登录状态，已安全重置并重新认证";
    }
    match prepared.state {
        AtrustClientDataState::Reusable => "检测到可复用的 aTrust 登录状态，优先免验证码登录",
        AtrustClientDataState::DeviceOnly => "已复用 aTrust 设备标识，将重新执行身份认证",
        AtrustClientDataState::Empty => "未检测到 aTrust 登录状态，将执行首次身份认证",
    }
}

/// 将 aTrust 启动阶段恢复为可重试的错误状态。
async fn mark_start_error(manager: &VpnManager) {
    let mut inner = manager.inner.lock().await;
    inner.atrust_status = VpnStatus::Error;
    inner.atrust_status_message = None;
    inner.atrust_captcha_submitted = false;
    inner.atrust_start_time = None;
    inner.atrust_ip = None;
    inner.atrust_stdin = None;
    inner.atrust_interface = None;
    inner.atrust_route_ready = false;
    inner.atrust_stack_ready = false;
}

/** 清理由旧版本或异常退出遗留的 zju-connect 进程。 */
async fn terminate_stale_client(sudo_password: &str) {
    let child = tokio::process::Command::new("sudo")
        .arg("-S")
        .arg("-p")
        .arg("")
        .arg("killall")
        .arg("zju-connect")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    if let Ok(mut child) = child {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin
                .write_all(format!("{sudo_password}\n").as_bytes())
                .await;
        }
        let _ = child.wait().await;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
}

/** 按本次受管 zju-connect 的独立进程组结束 sudo 包装器和 root 子进程。 */
async fn terminate_managed_client(sudo_password: &str, process_id: u32) {
    let process_group = format!("-{process_id}");
    for signal in ["-TERM", "-KILL"] {
        let child = tokio::process::Command::new("sudo")
            .arg("-S")
            .arg("-p")
            .arg("")
            .arg("kill")
            .arg(signal)
            .arg(&process_group)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        if let Ok(mut child) = child {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin
                    .write_all(format!("{sudo_password}\n").as_bytes())
                    .await;
            }
            let _ = child.wait().await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    }
}

/** 验证指定目标是否确实由 aTrust 创建的虚拟接口承载。 */
async fn route_uses_interface(route: &str, interface_name: &str) -> bool {
    let destination = route.split('/').next().unwrap_or(route);
    tokio::process::Command::new("route")
        .args(["-n", "get", destination])
        .output()
        .await
        .map(|output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .any(|line| line.trim() == format!("interface: {interface_name}"))
        })
        .unwrap_or(false)
}

/** 仅当虚拟 IP、虚拟接口和至少一条服务端路由均就绪时标记长沙 VPN 可用。 */
async fn emit_connected_if_ready(manager: &Arc<Mutex<VpnManagerInner>>, app_handle: &AppHandle) {
    let virtual_ip = {
        let mut inner = manager.lock().await;
        if inner.atrust_status == VpnStatus::Connected
            || inner.atrust_ip.is_none()
            || inner.atrust_interface.is_none()
            || !inner.atrust_route_ready
            || !inner.atrust_stack_ready
        {
            return;
        }
        inner.atrust_status = VpnStatus::Connected;
        inner.atrust_status_message = None;
        inner.atrust_captcha_submitted = false;
        inner.atrust_ip.clone()
    };

    let _ = app_handle.emit(
        "vpn-status-changed",
        VpnStatePayload {
            vpn_type: VpnType::Atrust,
            status: VpnStatus::Connected,
            message: "长沙服务器 VPN 已连接，内网路由已就绪".to_string(),
            virtual_ip,
            uptime: 0,
        },
    );
}

/** 仅识别 zju-connect 真正会阻塞等待 stdin 的短信码或 TOTP 提示。 */
fn is_mfa_prompt(text: &str) -> bool {
    let lower_text = text.to_lowercase();
    [
        "please enter the sms verification code",
        "please enter your sms code",
        "please enter your totp code",
        "请输入短信验证码",
        "请输入二次验证码",
        "请输入 totp 验证码",
    ]
    .iter()
    .any(|prompt| lower_text.contains(prompt))
}

/// 统一处理 zju-connect 的 stdout/stderr，Go 标准日志默认写入 stderr。
async fn handle_client_log(
    text: String,
    manager: &Arc<Mutex<VpnManagerInner>>,
    app_handle: &AppHandle,
) {
    let lower_text = text.to_lowercase();
    emit_vpn_log(app_handle, VpnType::Atrust, text.clone());

    if lower_text.contains("received client resource")
        || lower_text.contains("given auth data")
        || lower_text.contains("sid:")
        || lower_text.contains("signkey:")
    {
        return;
    }

    if lower_text.contains("captcha code received from browser") {
        manager.lock().await.atrust_captcha_submitted = true;
        return;
    }

    if let Some(server_message) = extract_atrust_server_error(&text) {
        let is_captcha_error = is_atrust_captcha_error(&server_message);
        let is_credential_error = is_atrust_credential_error(&server_message);
        let status = {
            let mut inner = manager.lock().await;
            let should_report =
                should_report_atrust_server_error(&server_message, inner.atrust_captcha_submitted);
            if !should_report {
                return;
            }
            inner.atrust_status_message = Some(server_message.clone());
            if is_captcha_error {
                inner.atrust_status = VpnStatus::Authenticating;
                inner.atrust_captcha_submitted = false;
            } else if is_credential_error {
                inner.atrust_status = VpnStatus::Error;
                inner.atrust_start_time = None;
                inner.atrust_captcha_submitted = false;
            }
            inner.atrust_status
        };

        emit_atrust_auth_feedback(app_handle, server_message.clone());
        if is_captcha_error || is_credential_error {
            let _ = app_handle.emit(
                "vpn-status-changed",
                VpnStatePayload {
                    vpn_type: VpnType::Atrust,
                    status,
                    message: server_message,
                    virtual_ip: None,
                    uptime: 0,
                },
            );
        }
        return;
    }

    let received_ip = text
        .split_once("Received IP:")
        .map(|(_, value)| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if let Some(ip) = received_ip {
        let mut inner = manager.lock().await;
        inner.atrust_ip = Some(ip.clone());
        drop(inner);
        emit_connected_if_ready(manager, app_handle).await;
    }

    if let Some((_, value)) = text.split_once("Interface Name:") {
        let interface_name = value
            .split(',')
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();
        if !interface_name.is_empty() {
            manager.lock().await.atrust_interface = Some(interface_name);
            emit_connected_if_ready(manager, app_handle).await;
        }
    }

    if let Some(route) = text
        .split_once("Add route to ")
        .map(|(_, value)| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        let (interface_name, route_already_ready) = {
            let inner = manager.lock().await;
            (inner.atrust_interface.clone(), inner.atrust_route_ready)
        };
        if route_already_ready {
            return;
        }
        if let Some(interface_name) = interface_name {
            for _ in 0..20 {
                if route_uses_interface(&route, &interface_name).await {
                    manager.lock().await.atrust_route_ready = true;
                    emit_connected_if_ready(manager, app_handle).await;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }

    if text.contains("Use DNS server ") || text.contains("No DNS server provided by server") {
        manager.lock().await.atrust_stack_ready = true;
        emit_connected_if_ready(manager, app_handle).await;
    }

    if text.contains("SOCKS5 server listening on") || text.contains("HTTP server listening on") {
        let _ = app_handle.emit(
            "vpn-status-changed",
            VpnStatePayload {
                vpn_type: VpnType::Atrust,
                status: VpnStatus::Connecting,
                message: "长沙服务器认证成功，正在配置内网路由...".to_string(),
                virtual_ip: manager.lock().await.atrust_ip.clone(),
                uptime: 0,
            },
        );
    }

    if let Some(pos) = text.find("http://127.0.0.1:") {
        let url = text[pos..]
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string();
        if !url.is_empty() {
            let mut inner = manager.lock().await;
            inner.atrust_status = VpnStatus::Authenticating;
            inner.atrust_captcha_submitted = false;
            drop(inner);
            let _ = app_handle.emit(
                "vpn-captcha-required",
                VpnCaptchaPayload {
                    vpn_type: VpnType::Atrust,
                    url,
                },
            );
        }
        return;
    }

    if is_mfa_prompt(&text) {
        manager.lock().await.atrust_status = VpnStatus::Authenticating;
        let _ = app_handle.emit(
            "vpn-status-changed",
            VpnStatePayload {
                vpn_type: VpnType::Atrust,
                status: VpnStatus::Authenticating,
                message: "等待二次验证...".to_string(),
                virtual_ip: None,
                uptime: 0,
            },
        );
        let _ = app_handle.emit(
            "vpn-auth-required",
            super::VpnAuthPayload {
                vpn_type: VpnType::Atrust,
                prompt: text,
            },
        );
    } else if lower_text.contains("incorrect password")
        || lower_text.contains("vpn client setup error")
        || lower_text.contains("login error:")
        || lower_text.contains("tun stack setup error")
    {
        let message = {
            let mut inner = manager.lock().await;
            let message = inner
                .atrust_status_message
                .clone()
                .unwrap_or_else(|| "长沙服务器 VPN 初始化失败，请检查日志".to_string());
            inner.atrust_status = VpnStatus::Error;
            inner.atrust_status_message = Some(message.clone());
            inner.atrust_captcha_submitted = false;
            inner.atrust_start_time = None;
            message
        };
        let _ = app_handle.emit(
            "vpn-status-changed",
            VpnStatePayload {
                vpn_type: VpnType::Atrust,
                status: VpnStatus::Error,
                message,
                virtual_ip: None,
                uptime: 0,
            },
        );
    }
}

/// 创建虚拟浏览器启动脚本以静默屏蔽外部浏览器打开
async fn setup_dummy_openers(dummy_bin_dir: &std::path::Path) -> Result<(), String> {
    std::fs::create_dir_all(dummy_bin_dir).map_err(|e| format!("无法创建 dummy_bin 目录: {e}"))?;

    let openers = vec![
        "open",
        "xdg-open",
        "sensible-browser",
        "x-www-browser",
        "gnome-open",
        "kde-open",
    ];
    let script_content = "#!/bin/sh\nexit 0\n";

    for opener in openers {
        let file_path = dummy_bin_dir.join(opener);
        std::fs::write(&file_path, script_content)
            .map_err(|e| format!("无法写入 dummy opener {opener}: {e}"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(&file_path) {
                let mut perms = metadata.permissions();
                perms.set_mode(0o755);
                let _ = std::fs::set_permissions(&file_path, perms);
            }
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn connect_atrust(
    app_handle: AppHandle,
    state: tauri::State<'_, VpnManager>,
    password: String,
) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let _config_guard = state.inner().config_operation_lock.lock().await;
        let atrust_config = load_vpn_config(app_handle.clone()).await?.atrust;
        validate_vpn_connection_config("aTrust", &atrust_config)?;
        let client_data_path = atrust_client_data_path(&app_handle)?;
        super::windows::connect_atrust(
            &app_handle,
            state.inner(),
            atrust_config,
            password,
            client_data_path,
        )
        .await
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Err("当前操作系统暂不支持 aTrust VPN 连接".to_string())
    }
    #[cfg(target_os = "macos")]
    {
        state.inner().ensure_connections_allowed()?;
        let config_guard = state.inner().config_operation_lock.lock().await;
        let zju_connect_bin = resolve_macos_sidecar("zju-connect")?;
        let atrust_config = load_vpn_config(app_handle.clone()).await?.atrust;
        validate_vpn_connection_config("aTrust", &atrust_config)?;
        let host = atrust_config.host;
        let port = atrust_config.port;
        let username = atrust_config.username;
        let sudo_pass = {
            let mut inner = state.inner.lock().await;
            if inner.atrust_status == VpnStatus::Connecting
                || inner.atrust_status == VpnStatus::Authenticating
                || inner.atrust_status == VpnStatus::Connected
            {
                return Err("aTrust VPN 已经连接或正在连接中".to_string());
            }

            let sudo_pass = inner
                .sudo_password
                .clone()
                .ok_or("请先配置并验证系统 Sudo 提权密码")?;

            inner.atrust_status = VpnStatus::Connecting;
            inner.atrust_status_message = None;
            inner.atrust_captcha_submitted = false;
            inner.atrust_start_time = Some(std::time::Instant::now());
            inner.atrust_ip = None;
            inner.atrust_interface = None;
            inner.atrust_route_ready = false;
            inner.atrust_stack_ready = false;
            sudo_pass
        };
        drop(config_guard);

        terminate_stale_client(&sudo_pass).await;
        if let Err(error) = state.inner().ensure_connections_allowed() {
            mark_start_error(&state).await;
            return Err(error);
        }

        let client_data_path = match atrust_client_data_path(&app_handle) {
            Ok(path) => path,
            Err(error) => {
                mark_start_error(&state).await;
                return Err(error);
            }
        };
        let repaired_legacy_owner =
            match repair_legacy_atrust_client_data_owner(&client_data_path, &sudo_pass).await {
                Ok(repaired) => repaired,
                Err(error) => {
                    mark_start_error(&state).await;
                    return Err(error);
                }
            };
        let prepared_client_data = match prepare_atrust_client_data(&client_data_path) {
            Ok(prepared) => prepared,
            Err(error) => {
                mark_start_error(&state).await;
                return Err(error);
            }
        };
        if repaired_legacy_owner {
            emit_vpn_log(
                &app_handle,
                VpnType::Atrust,
                "已迁移旧版 aTrust 登录状态文件并收紧访问权限",
            );
        }
        emit_vpn_log(
            &app_handle,
            VpnType::Atrust,
            atrust_client_data_log(&prepared_client_data),
        );

        // 2. 创建内存中的 FIFO 管道
        let rand_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let pipe_path = format!("/tmp/atrust-config-{rand_id}");

        let status = match tokio::process::Command::new("mkfifo")
            .arg(&pipe_path)
            .status()
            .await
        {
            Ok(status) => status,
            Err(error) => {
                mark_start_error(&state).await;
                return Err(format!("创建 FIFO 管道失败: {error}"));
            }
        };

        if !status.success() {
            mark_start_error(&state).await;
            return Err("创建 FIFO 管道退出异常".to_string());
        }
        state.inner.lock().await.atrust_fifo_path = Some(std::path::PathBuf::from(&pipe_path));

        // 设置管道权限
        let _ = tokio::process::Command::new("chmod")
            .arg("600")
            .arg(&pipe_path)
            .status()
            .await;

        // 3. 构建 TOML 配置文本
        let runtime_dir = client_data_path
            .parent()
            .ok_or_else(|| "aTrust 登录状态路径缺少父目录".to_string())?
            .to_path_buf();

        // 动态生成虚拟的外部浏览器打开命令
        let dummy_bin_dir = runtime_dir.join("dummy_bin");
        if let Err(error) = setup_dummy_openers(&dummy_bin_dir).await {
            let _ = tokio::fs::remove_file(&pipe_path).await;
            state.inner.lock().await.atrust_fifo_path = None;
            mark_start_error(&state).await;
            return Err(error);
        }

        // 只复用 zju-connect 的 client_data（Cookie + 设备 ID）。
        // 不配置 SID/resourceData，确保服务端资源和隧道信息每次都重新获取；
        // Cookie 过期时 zju-connect 会在同一次启动中自动回退到 auth/psw。
        let toml_config = format!(
            r#"protocol = "atrust"
server_address = "{}"
server_port = {}
username = "{}"
password = "{}"
disable_zju_config = true
socks_bind = ""
http_bind = ""
tcp_tunnel_mode = false
tun_mode = true
add_route = true
dns_hijack = false
fake_ip = false
debug_dump = {}
auth_type = "auth/psw"
login_domain = "local"
client_data_file = "{}"
"#,
            toml_escape(&host),
            port,
            toml_escape(&username),
            toml_escape(&password),
            cfg!(debug_assertions),
            toml_escape(&client_data_path.to_string_lossy())
        );

        // 4. 先启动客户端，再启动 FIFO 写入端；这样客户端启动失败时不会留下永久阻塞的 writer。
        let env_path =
            std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin:/usr/sbin:/sbin".to_string());
        let path_env = format!("PATH={}:{}", dummy_bin_dir.to_string_lossy(), env_path);

        if let Err(error) = state.inner().ensure_connections_allowed() {
            let _ = tokio::fs::remove_file(&pipe_path).await;
            state.inner.lock().await.atrust_fifo_path = None;
            mark_start_error(&state).await;
            return Err(error);
        }

        let mut command = tokio::process::Command::new("sudo");
        command
            .arg("-S")
            .arg(path_env)
            .arg(&zju_connect_bin)
            .arg("-config")
            .arg(&pipe_path)
            .env(
                "PATH",
                format!("{}:{}", dummy_bin_dir.to_string_lossy(), env_path),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        command.process_group(0);
        let child_result = command.spawn();

        let mut child = match child_result {
            Ok(child) => child,
            Err(error) => {
                let _ = tokio::fs::remove_file(&pipe_path).await;
                state.inner.lock().await.atrust_fifo_path = None;
                mark_start_error(&state).await;
                return Err(format!("启动 zju-connect 失败: {error}"));
            }
        };

        if let Err(error) = state.inner().ensure_connections_allowed() {
            if let Some(process_id) = child.id() {
                terminate_managed_client(&sudo_pass, process_id).await;
            }
            let _ = child.kill().await;
            let _ = tokio::fs::remove_file(&pipe_path).await;
            state.inner.lock().await.atrust_fifo_path = None;
            mark_start_error(&state).await;
            return Err(error);
        }

        let pipe_path_writer = pipe_path.clone();
        let writer = tokio::task::spawn_blocking(move || -> Result<(), String> {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&pipe_path_writer)
                .map_err(|error| format!("打开 aTrust 配置管道失败: {error}"))?;
            file.write_all(toml_config.as_bytes())
                .map_err(|error| format!("写入 aTrust 配置管道失败: {error}"))?;
            file.flush()
                .map_err(|error| format!("刷新 aTrust 配置管道失败: {error}"))
        });

        // 5. 往 stdin 喂入 sudo 密码，并保留同一 stdin 供后续 MFA 交互。
        let mut stdin = match child.stdin.take() {
            Some(stdin) => stdin,
            None => {
                let _ = child.kill().await;
                terminate_stale_client(&sudo_pass).await;
                let _ = tokio::fs::remove_file(&pipe_path).await;
                state.inner.lock().await.atrust_fifo_path = None;
                mark_start_error(&state).await;
                return Err("无法获取 zju-connect stdin".to_string());
            }
        };
        if let Err(error) = stdin.write_all(format!("{sudo_pass}\n").as_bytes()).await {
            let _ = child.kill().await;
            terminate_stale_client(&sudo_pass).await;
            let _ = tokio::fs::remove_file(&pipe_path).await;
            state.inner.lock().await.atrust_fifo_path = None;
            mark_start_error(&state).await;
            return Err(format!("向 sudo 写入提权凭据失败: {error}"));
        }

        let (stdout, stderr) = match (child.stdout.take(), child.stderr.take()) {
            (Some(stdout), Some(stderr)) => (stdout, stderr),
            _ => {
                let _ = child.kill().await;
                terminate_stale_client(&sudo_pass).await;
                let _ = tokio::fs::remove_file(&pipe_path).await;
                state.inner.lock().await.atrust_fifo_path = None;
                mark_start_error(&state).await;
                return Err("无法读取 zju-connect 日志".to_string());
            }
        };

        let manager_clone = state.inner.clone();
        let app_handle_clone = app_handle.clone();
        let pipe_path_cleanup = pipe_path.clone();
        let pipe_manager = state.inner.clone();

        // FIFO 只能在 zju-connect 完成读取后删除，不能在 watcher 启动时抢先删除。
        tokio::spawn(async move {
            let _ = writer.await;
            let _ = tokio::fs::remove_file(&pipe_path_cleanup).await;
            let mut inner = pipe_manager.lock().await;
            if inner.atrust_fifo_path.as_deref() == Some(std::path::Path::new(&pipe_path_cleanup)) {
                inner.atrust_fifo_path = None;
            }
        });

        // 监控日志和进程状态的协程
        let watcher = tokio::spawn(async move {
            let mut reader_out = BufReader::new(stdout).lines();
            let mut reader_err = BufReader::new(stderr).lines();

            loop {
                tokio::select! {
                    line = reader_out.next_line() => {
                        match line {
                            Ok(Some(text)) => {
                                handle_client_log(text, &manager_clone, &app_handle_clone).await;
                            }
                            _ => break,
                        }
                    }
                    line = reader_err.next_line() => {
                        match line {
                            Ok(Some(text)) => {
                                handle_client_log(text, &manager_clone, &app_handle_clone).await;
                            }
                            _ => break,
                        }
                    }
                }
            }

            // 进程退出处理
            let mut inner_lock = manager_clone.lock().await;
            let exit_status = if inner_lock.atrust_status == VpnStatus::Disconnecting {
                VpnStatus::Disconnected
            } else {
                VpnStatus::Error
            };
            let exit_message = if exit_status == VpnStatus::Error {
                inner_lock
                    .atrust_status_message
                    .clone()
                    .unwrap_or_else(|| "aTrust 进程意外退出，请检查日志".to_string())
            } else {
                inner_lock.atrust_status_message = None;
                "已断开".to_string()
            };
            inner_lock.atrust_status = exit_status;
            inner_lock.atrust_captcha_submitted = false;
            inner_lock.atrust_ip = None;
            inner_lock.atrust_start_time = None;
            inner_lock.atrust_stdin = None;
            inner_lock.atrust_child = None;
            inner_lock.atrust_interface = None;
            inner_lock.atrust_route_ready = false;
            inner_lock.atrust_stack_ready = false;

            let _ = app_handle_clone.emit(
                "vpn-status-changed",
                VpnStatePayload {
                    vpn_type: VpnType::Atrust,
                    status: exit_status,
                    message: exit_message,
                    virtual_ip: None,
                    uptime: 0,
                },
            );
        });

        let readiness_manager = state.inner.clone();
        let readiness_app = app_handle.clone();
        let readiness_watcher = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(45)).await;
            let should_report = {
                let mut inner = readiness_manager.lock().await;
                if inner.atrust_status != VpnStatus::Connecting {
                    false
                } else {
                    inner.atrust_status = VpnStatus::Error;
                    inner.atrust_status_message =
                        Some("长沙服务器已登录，但内网路由未就绪，请检查日志".to_string());
                    inner.atrust_captcha_submitted = false;
                    inner.atrust_start_time = None;
                    true
                }
            };
            if should_report {
                let _ = readiness_app.emit(
                    "vpn-status-changed",
                    VpnStatePayload {
                        vpn_type: VpnType::Atrust,
                        status: VpnStatus::Error,
                        message: "长沙服务器已登录，但内网路由未就绪，请检查日志".to_string(),
                        virtual_ip: None,
                        uptime: 0,
                    },
                );
            }
        });

        let mut stdin = Some(stdin);
        let mut child = Some(child);
        let mut watcher = Some(watcher);
        let mut readiness_watcher = Some(readiness_watcher);
        let should_abort_for_shutdown = {
            let mut inner = state.inner.lock().await;
            if state.inner().is_shutting_down() {
                true
            } else {
                inner.atrust_stdin = stdin.take();
                inner.atrust_child = child.take();
                inner.atrust_watcher = watcher.take();
                inner.atrust_readiness_watcher = readiness_watcher.take();
                false
            }
        };

        if should_abort_for_shutdown {
            if let Some(watcher) = watcher {
                watcher.abort();
            }
            if let Some(readiness_watcher) = readiness_watcher {
                readiness_watcher.abort();
            }
            if let Some(mut child) = child {
                if let Some(process_id) = child.id() {
                    terminate_managed_client(&sudo_pass, process_id).await;
                }
                let _ = child.kill().await;
            }
            let _ = tokio::fs::remove_file(&pipe_path).await;
            let mut inner = state.inner.lock().await;
            inner.atrust_fifo_path = None;
            inner.atrust_status = VpnStatus::Disconnected;
            inner.atrust_status_message = None;
            inner.atrust_captcha_submitted = false;
            inner.atrust_start_time = None;
            inner.atrust_ip = None;
            return Err("应用正在安全退出，已回收 aTrust 连接进程".to_string());
        }

        Ok(())
    }
}

/** 断开 aTrust，并回收守护任务和 FIFO 临时资源。 */
pub async fn disconnect_atrust_managed(
    app_handle: &AppHandle,
    manager: &VpnManager,
) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        super::windows::disconnect(app_handle, manager, VpnType::Atrust).await
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = (app_handle, manager);
        Err("当前操作系统暂不支持 aTrust VPN 断开".to_string())
    }
    #[cfg(target_os = "macos")]
    {
        let (child, watcher, readiness_watcher, fifo_path, sudo_pass) = {
            let mut inner = manager.inner.lock().await;
            let sudo_pass = inner
                .sudo_password
                .clone()
                .ok_or("断开 aTrust 前需要重新验证 macOS 提权密码")?;
            inner.atrust_status = VpnStatus::Disconnecting;
            inner.atrust_stdin = None;
            (
                inner.atrust_child.take(),
                inner.atrust_watcher.take(),
                inner.atrust_readiness_watcher.take(),
                inner.atrust_fifo_path.take(),
                sudo_pass,
            )
        };

        // 不持有全局状态锁执行进程操作，保证状态查询和其他 VPN 仍可响应。
        let has_managed_child = child.is_some();
        if let Some(mut child) = child {
            if let Some(process_id) = child.id() {
                terminate_managed_client(&sudo_pass, process_id).await;
            }
            let _ = child.kill().await;
        }

        if let Some(watcher) = watcher {
            watcher.abort();
        }
        if let Some(readiness_watcher) = readiness_watcher {
            readiness_watcher.abort();
        }
        if let Some(fifo_path) = fifo_path {
            let _ = tokio::fs::remove_file(fifo_path).await;
        }

        if !has_managed_child {
            terminate_stale_client(&sudo_pass).await;
        }

        {
            let mut inner = manager.inner.lock().await;
            inner.atrust_status = VpnStatus::Disconnected;
            inner.atrust_status_message = None;
            inner.atrust_captcha_submitted = false;
            inner.atrust_ip = None;
            inner.atrust_start_time = None;
            inner.atrust_interface = None;
            inner.atrust_route_ready = false;
            inner.atrust_stack_ready = false;
        }

        let _ = app_handle.emit(
            "vpn-status-changed",
            VpnStatePayload {
                vpn_type: VpnType::Atrust,
                status: VpnStatus::Disconnected,
                message: "已断开".to_string(),
                virtual_ip: None,
                uptime: 0,
            },
        );

        Ok(())
    }
}

/** 提供给前端的 aTrust 断开命令。 */
#[tauri::command]
pub async fn disconnect_atrust(
    app_handle: AppHandle,
    state: tauri::State<'_, VpnManager>,
) -> Result<(), String> {
    disconnect_atrust_managed(&app_handle, state.inner()).await
}

#[cfg(test)]
mod tests {
    use super::{is_mfa_prompt, toml_escape};
    #[cfg(target_os = "macos")]
    use super::{prepare_atrust_client_data, AtrustClientDataState};

    /// 验证密码中的 TOML 特殊字符不会逃逸出字符串值。
    #[test]
    fn escapes_toml_basic_string_content() {
        assert_eq!(toml_escape("a\\b\"c\nd\r"), "a\\\\b\\\"c\\nd\\r");
    }

    /** 确保资源 JSON 中的 OTP 字段不会被误判为二次认证提示。 */
    #[test]
    fn ignores_otp_fields_in_resource_diagnostics() {
        assert!(!is_mfa_prompt(
            r#"Received client resource: {"enableOtp":1,"mfa":true}"#
        ));
        assert!(is_mfa_prompt("Please enter the SMS verification code: "));
    }

    /** 验证客户端数据文件权限会收紧，损坏内容会在启动前重置。 */
    #[cfg(target_os = "macos")]
    #[test]
    fn protects_and_repairs_atrust_client_data_file() {
        use std::os::unix::fs::PermissionsExt;

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let test_directory = std::env::temp_dir().join(format!(
            "yuyan-atrust-client-data-test-{}-{nonce}",
            std::process::id()
        ));
        let client_data_path = test_directory
            .join(".runtime")
            .join("atrust-client-data.json");

        let initial = prepare_atrust_client_data(&client_data_path).expect("应创建客户端数据");
        assert_eq!(initial.state, AtrustClientDataState::Empty);
        assert_eq!(
            std::fs::metadata(&client_data_path)
                .expect("应读取客户端数据权限")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(client_data_path.parent().expect("应有父目录"))
                .expect("应读取运行目录权限")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        std::fs::write(&client_data_path, b"not-json").expect("应写入损坏样本");
        let repaired = prepare_atrust_client_data(&client_data_path).expect("应修复客户端数据");
        assert!(repaired.reset_invalid);
        assert_eq!(
            std::fs::read(&client_data_path).expect("应读取修复结果"),
            b"{}"
        );

        std::fs::remove_dir_all(&test_directory).expect("应清理测试目录");
    }
}
