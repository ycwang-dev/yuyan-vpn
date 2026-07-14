mod helper;
mod ipc;

use self::ipc::{HelperCommand, HelperEnvelope, HelperResponse, HELPER_ARGUMENT};
use super::{
    emit_vpn_log, VpnAuthPayload, VpnConfig, VpnManager, VpnStatePayload, VpnStatus, VpnType,
};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::ClientOptions;
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

/** 单条 UI→helper IPC 报文上限。 */
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/** 在 Tauri 启动前识别内部 helper 参数；命中时只运行管理员后端，不创建 WebView。 */
pub fn run_helper_if_requested() -> bool {
    let args = std::env::args().collect::<Vec<_>>();
    let Some(index) = args.iter().position(|value| value == HELPER_ARGUMENT) else {
        return false;
    };
    let Some(token) = args.get(index + 1).cloned() else {
        return true;
    };
    let Some(parent_pid) = args
        .get(index + 2)
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return true;
    };
    if !is_valid_token(&token) {
        return true;
    }

    let pipe_name = helper_pipe_name(&token);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    match runtime {
        Ok(runtime) => {
            if let Err(error) = runtime.block_on(helper::run(pipe_name, token, parent_pid)) {
                eprintln!("Windows VPN helper 退出: {error}");
            }
        }
        Err(error) => eprintln!("创建 Windows VPN helper 运行时失败: {error}"),
    }
    true
}

/** 请求 UAC 启动或复用当前管理员 helper 会话。 */
pub async fn ensure_helper(manager: &VpnManager) -> Result<(), String> {
    let _start_guard = manager.windows_helper_start_lock.lock().await;
    if helper_is_available(manager).await {
        return Ok(());
    }

    let token = create_session_token()?;
    let pipe_name = helper_pipe_name(&token);
    launch_elevated_helper(&token)?;

    let mut last_error = None;
    for _ in 0..240 {
        match send_request(&pipe_name, &token, HelperCommand::Ping).await {
            Ok(response) if response.success => {
                let mut inner = manager.inner.lock().await;
                inner.windows_helper_pipe = Some(pipe_name);
                inner.windows_helper_token = Some(token);
                return Ok(());
            }
            Ok(response) => last_error = response.error,
            Err(error) => last_error = Some(error),
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    Err(last_error.unwrap_or_else(|| "等待 Windows UAC helper 启动超时".to_string()))
}

/** 检查当前 helper 会话是否仍可响应，不把 UAC 状态伪装成 sudo 密码。 */
pub async fn helper_is_available(manager: &VpnManager) -> bool {
    let session = {
        let inner = manager.inner.lock().await;
        inner
            .windows_helper_pipe
            .clone()
            .zip(inner.windows_helper_token.clone())
    };
    let Some((pipe_name, token)) = session else {
        return false;
    };
    let _request_guard = manager.windows_request_lock.lock().await;
    match send_request(&pipe_name, &token, HelperCommand::Ping).await {
        Ok(response) if response.success => true,
        _ => {
            let mut inner = manager.inner.lock().await;
            inner.windows_helper_pipe = None;
            inner.windows_helper_token = None;
            false
        }
    }
}

/** 通过 helper 启动 Fortinet，并同步初始状态。 */
pub async fn connect_fortinet(
    app_handle: &AppHandle,
    manager: &VpnManager,
    config: VpnConfig,
    password: String,
) -> Result<(), String> {
    manager.ensure_connections_allowed()?;
    ensure_helper(manager).await?;
    let response =
        request_with_session(manager, HelperCommand::ConnectFortinet { config, password }).await?;
    apply_response(app_handle, manager, response).await
}

/** 通过 helper 启动 aTrust，并同步初始状态。 */
pub async fn connect_atrust(
    app_handle: &AppHandle,
    manager: &VpnManager,
    config: VpnConfig,
    password: String,
) -> Result<(), String> {
    manager.ensure_connections_allowed()?;
    ensure_helper(manager).await?;
    let response =
        request_with_session(manager, HelperCommand::ConnectAtrust { config, password }).await?;
    apply_response(app_handle, manager, response).await
}

/** 断开指定 Windows VPN，并等待 helper 完成路由/适配器清理。 */
pub async fn disconnect(
    app_handle: &AppHandle,
    manager: &VpnManager,
    vpn_type: VpnType,
) -> Result<(), String> {
    if !helper_is_available(manager).await {
        reset_manager_engine(manager, vpn_type).await;
        return Ok(());
    }
    let response = request_with_session(manager, HelperCommand::Disconnect { vpn_type }).await?;
    apply_response(app_handle, manager, response).await
}

/** 把 aTrust MFA 码经命名管道写入管理员子进程 stdin。 */
pub async fn submit_mfa(manager: &VpnManager, code: String) -> Result<(), String> {
    let response = request_with_session(manager, HelperCommand::SubmitMfa { code }).await?;
    if response.success {
        Ok(())
    } else {
        Err(response
            .error
            .unwrap_or_else(|| "Windows aTrust MFA 提交失败".to_string()))
    }
}

/** 刷新 helper 快照、增量日志和 MFA 事件。 */
pub async fn refresh(app_handle: &AppHandle, manager: &VpnManager) -> Result<(), String> {
    if !helper_is_available(manager).await {
        return Ok(());
    }
    let response = request_with_session(manager, HelperCommand::Snapshot).await?;
    apply_response(app_handle, manager, response).await
}

/** 请求 helper 优雅关闭双 VPN，随后 Job Object 兜底回收所有引擎。 */
pub async fn shutdown_helper(app_handle: &AppHandle, manager: &VpnManager) -> Result<(), String> {
    if !helper_is_available(manager).await {
        reset_manager_engine(manager, VpnType::Fortinet).await;
        reset_manager_engine(manager, VpnType::Atrust).await;
        return Ok(());
    }
    let response = request_with_session(manager, HelperCommand::Shutdown).await?;
    let apply_result = apply_response(app_handle, manager, response).await;
    let mut inner = manager.inner.lock().await;
    inner.windows_helper_pipe = None;
    inner.windows_helper_token = None;
    apply_result
}

/** 使用当前 manager 中的管道会话执行命令。 */
async fn request_with_session(
    manager: &VpnManager,
    command: HelperCommand,
) -> Result<HelperResponse, String> {
    let _request_guard = manager.windows_request_lock.lock().await;
    let (pipe_name, token) = {
        let inner = manager.inner.lock().await;
        inner
            .windows_helper_pipe
            .clone()
            .zip(inner.windows_helper_token.clone())
            .ok_or_else(|| "Windows 管理员 helper 尚未授权".to_string())?
    };
    send_request(&pipe_name, &token, command).await
}

/** 通过长度前缀 JSON 协议执行一次命名管道请求。 */
async fn send_request(
    pipe_name: &str,
    token: &str,
    command: HelperCommand,
) -> Result<HelperResponse, String> {
    let mut pipe = ClientOptions::new()
        .open(pipe_name)
        .map_err(|error| format!("连接 Windows VPN helper 失败: {error}"))?;
    let envelope = HelperEnvelope {
        token: token.to_string(),
        command,
    };
    let payload = serde_json::to_vec(&envelope)
        .map_err(|error| format!("序列化 Windows VPN helper 请求失败: {error}"))?;
    if payload.len() > MAX_MESSAGE_BYTES {
        return Err("Windows VPN helper 请求超过安全上限".to_string());
    }
    pipe.write_u32_le(payload.len() as u32)
        .await
        .map_err(|error| format!("写入 Windows VPN helper 请求长度失败: {error}"))?;
    pipe.write_all(&payload)
        .await
        .map_err(|error| format!("写入 Windows VPN helper 请求失败: {error}"))?;
    pipe.flush()
        .await
        .map_err(|error| format!("刷新 Windows VPN helper 请求失败: {error}"))?;

    let response_length = pipe
        .read_u32_le()
        .await
        .map_err(|error| format!("读取 Windows VPN helper 响应长度失败: {error}"))?
        as usize;
    if response_length == 0 || response_length > MAX_MESSAGE_BYTES {
        return Err("Windows VPN helper 响应大小非法".to_string());
    }
    let mut response = vec![0_u8; response_length];
    pipe.read_exact(&mut response)
        .await
        .map_err(|error| format!("读取 Windows VPN helper 响应失败: {error}"))?;
    serde_json::from_slice(&response)
        .map_err(|error| format!("解析 Windows VPN helper 响应失败: {error}"))
}

/** 把 helper 响应合并到现有跨平台状态机并发送前端事件。 */
async fn apply_response(
    app_handle: &AppHandle,
    manager: &VpnManager,
    response: HelperResponse,
) -> Result<(), String> {
    if !response.success {
        return Err(response
            .error
            .unwrap_or_else(|| "Windows VPN helper 操作失败".to_string()));
    }

    let (new_logs, auth_prompt, changed_states) = {
        let mut inner = manager.inner.lock().await;
        let previous_fortinet = inner.fortinet_status;
        let previous_atrust = inner.atrust_status;
        update_start_time(
            response.snapshot.fortinet.status,
            &mut inner.fortinet_start_time,
        );
        update_start_time(
            response.snapshot.atrust.status,
            &mut inner.atrust_start_time,
        );
        inner.fortinet_status = response.snapshot.fortinet.status;
        inner.fortinet_ip = response.snapshot.fortinet.virtual_ip.clone();
        inner.atrust_status = response.snapshot.atrust.status;
        inner.atrust_ip = response.snapshot.atrust.virtual_ip.clone();

        let logs = response
            .logs
            .into_iter()
            .filter(|item| item.sequence > inner.windows_log_sequence)
            .collect::<Vec<_>>();
        if let Some(last) = logs.last() {
            inner.windows_log_sequence = last.sequence;
        }
        let prompt = if response.snapshot.auth_sequence > inner.windows_auth_sequence {
            inner.windows_auth_sequence = response.snapshot.auth_sequence;
            response.snapshot.auth_prompt.clone()
        } else {
            None
        };
        (
            logs,
            prompt,
            [
                (
                    VpnType::Fortinet,
                    previous_fortinet,
                    inner.fortinet_status,
                    inner.fortinet_ip.clone(),
                ),
                (
                    VpnType::Atrust,
                    previous_atrust,
                    inner.atrust_status,
                    inner.atrust_ip.clone(),
                ),
            ],
        )
    };

    for log in new_logs {
        emit_vpn_log(app_handle, log.vpn_type, log.text);
    }
    for (vpn_type, previous, status, virtual_ip) in changed_states {
        if previous != status {
            let _ = app_handle.emit(
                "vpn-status-changed",
                VpnStatePayload {
                    vpn_type,
                    status,
                    message: windows_status_message(vpn_type, status).to_string(),
                    virtual_ip,
                    uptime: 0,
                },
            );
        }
    }
    if let Some(prompt) = auth_prompt {
        let _ = app_handle.emit(
            "vpn-auth-required",
            VpnAuthPayload {
                vpn_type: VpnType::Atrust,
                prompt,
            },
        );
    }
    Ok(())
}

/** 根据 helper 状态维护 UI 侧连接计时起点。 */
fn update_start_time(status: VpnStatus, start_time: &mut Option<std::time::Instant>) {
    if matches!(
        status,
        VpnStatus::Connecting | VpnStatus::Authenticating | VpnStatus::Connected
    ) {
        if start_time.is_none() {
            *start_time = Some(std::time::Instant::now());
        }
    } else {
        *start_time = None;
    }
}

/** 清理 UI 侧指定引擎状态。 */
async fn reset_manager_engine(manager: &VpnManager, vpn_type: VpnType) {
    let mut inner = manager.inner.lock().await;
    match vpn_type {
        VpnType::Fortinet => {
            inner.fortinet_status = VpnStatus::Disconnected;
            inner.fortinet_ip = None;
            inner.fortinet_start_time = None;
        }
        VpnType::Atrust => {
            inner.atrust_status = VpnStatus::Disconnected;
            inner.atrust_ip = None;
            inner.atrust_start_time = None;
        }
    }
}

/** 使用操作系统密码学随机源生成 128 位 helper 会话令牌。 */
fn create_session_token() -> Result<String, String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|error| format!("生成 Windows helper 会话令牌失败: {error}"))?;
    Ok(bytes.iter().map(|value| format!("{value:02x}")).collect())
}

/** 校验内部 helper 参数，禁止把任意文本拼进命名管道路径。 */
fn is_valid_token(token: &str) -> bool {
    (16..=64).contains(&token.len()) && token.bytes().all(|value| value.is_ascii_hexdigit())
}

/** 根据会话令牌生成仅限本机的命名管道路径。 */
fn helper_pipe_name(token: &str) -> String {
    format!(r"\\.\pipe\yuyan-swift-vpn-{token}")
}

/** 通过 Windows UAC 的 runas 动词启动同一签名 exe 的 helper 模式。 */
fn launch_elevated_helper(token: &str) -> Result<(), String> {
    let executable =
        std::env::current_exe().map_err(|error| format!("获取 Windows 应用路径失败: {error}"))?;
    let parameters = format!("{HELPER_ARGUMENT} {token} {}", std::process::id());
    let operation = wide("runas");
    let executable = wide(executable.as_os_str());
    let parameters = wide(&parameters);
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            executable.as_ptr(),
            parameters.as_ptr(),
            std::ptr::null(),
            SW_HIDE,
        )
    };
    if result as isize <= 32 {
        return Err("Windows 管理员授权被取消或 helper 启动失败".to_string());
    }
    Ok(())
}

/** 把 Rust 字符串转换为 Win32 API 使用的 UTF-16 NUL 结尾缓冲区。 */
fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/** 返回 Windows 前端状态文案。 */
fn windows_status_message(vpn_type: VpnType, status: VpnStatus) -> &'static str {
    match (vpn_type, status) {
        (_, VpnStatus::Disconnected) => "未连接",
        (_, VpnStatus::Connecting) => "正在建立 Windows Wintun 安全通道...",
        (VpnType::Atrust, VpnStatus::Authenticating) => "等待二次验证...",
        (VpnType::Fortinet, VpnStatus::Authenticating) => "正在认证 FortiGate...",
        (_, VpnStatus::Connected) => "已连接，Windows 内网路由已就绪",
        (_, VpnStatus::Disconnecting) => "正在清理 Windows 路由与虚拟网卡...",
        (_, VpnStatus::Error) => "连接出错，请检查日志",
    }
}

#[cfg(test)]
mod tests {
    use super::{create_session_token, is_valid_token};

    /** 会话令牌必须来自 128 位随机值并满足管道名字符约束。 */
    #[test]
    fn creates_valid_random_session_token() {
        let first = create_session_token().expect("应生成 helper 会话令牌");
        let second = create_session_token().expect("应生成第二个 helper 会话令牌");
        assert_eq!(first.len(), 32);
        assert!(is_valid_token(&first));
        assert_ne!(first, second);
    }
}
