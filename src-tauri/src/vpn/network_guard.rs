use serde_json::{json, Value};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

/** Clash Verge Rev 默认的 Mihomo 控制套接字。 */
const MIHOMO_CONTROL_SOCKET: &str = "/tmp/verge/verge-mihomo.sock";
/** curl 无法连接目标控制端时使用的退出码。 */
const CURL_FAILED_TO_CONNECT_EXIT_CODE: i32 = 7;
/** 初始读取 Mihomo 配置时允许的总尝试次数。 */
const MIHOMO_READ_ATTEMPTS: usize = 3;
/** Mihomo 启动或重载期间的配置读取重试间隔。 */
const MIHOMO_READ_RETRY_DELAY: Duration = Duration::from_millis(200);

/** Fortinet 连接前保存的 Mihomo 出口状态。 */
#[derive(Clone)]
pub struct MihomoRouteState {
    tun: Value,
}

/** Mihomo 控制接口请求失败类型。 */
#[derive(Debug, PartialEq, Eq)]
enum MihomoRequestError {
    /** Unix Socket 当前无法建立连接。 */
    Unavailable(String),
    /** 控制接口已响应异常、数据无效或本机调用失败。 */
    Failed(String),
}

impl MihomoRequestError {
    /** 返回可展示给用户的完整错误信息。 */
    fn into_message(self) -> String {
        match self {
            Self::Unavailable(message) | Self::Failed(message) => message,
        }
    }

    /** 借用可展示给用户的完整错误信息。 */
    fn message(&self) -> &str {
        match self {
            Self::Unavailable(message) | Self::Failed(message) => message,
        }
    }

    /** 判断错误是否仅表示控制端当前不可连接。 */
    fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unavailable(_))
    }
}

/** 修改 Mihomo TUN 的自动接口探测开关。 */
fn set_auto_detect_interface(tun: &mut Value, enabled: bool) -> Result<(), String> {
    let tun_object = tun.as_object_mut().ok_or("Mihomo TUN 配置格式无效")?;
    tun_object.insert("auto-detect-interface".to_string(), Value::Bool(enabled));
    Ok(())
}

/** 根据 curl 退出码区分控制端不可连接与其它请求失败。 */
fn classify_mihomo_request_failure(exit_code: Option<i32>, stderr: &str) -> MihomoRequestError {
    let detail = if stderr.trim().is_empty() {
        "curl 未返回错误详情"
    } else {
        stderr.trim()
    };
    let message = format!("Mihomo 控制接口返回失败: {detail}");
    if exit_code == Some(CURL_FAILED_TO_CONNECT_EXIT_CODE) {
        MihomoRequestError::Unavailable(message)
    } else {
        MihomoRequestError::Failed(message)
    }
}

/** 通过指定 Unix Socket 调用 Mihomo 控制接口。 */
async fn request_mihomo_at(
    socket_path: &Path,
    method: &str,
    body: Option<&Value>,
) -> Result<String, MihomoRequestError> {
    let mut command = tokio::process::Command::new("/usr/bin/curl");
    command
        .arg("--silent")
        .arg("--show-error")
        .arg("--fail-with-body")
        .arg("--connect-timeout")
        .arg("1")
        .arg("--max-time")
        .arg("2")
        .arg("--unix-socket")
        .arg(socket_path)
        .arg("--request")
        .arg(method)
        .arg("http://localhost/configs")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(body) = body {
        command
            .arg("--header")
            .arg("Content-Type: application/json")
            .arg("--data")
            .arg(body.to_string());
    }

    let output = command.output().await.map_err(|error| {
        MihomoRequestError::Failed(format!("无法调用 Mihomo 控制接口: {error}"))
    })?;
    if !output.status.success() {
        return Err(classify_mihomo_request_failure(
            output.status.code(),
            &String::from_utf8_lossy(&output.stderr),
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/** 通过 Clash Verge Rev 默认 Unix Socket 调用 Mihomo 控制接口。 */
async fn request_mihomo(method: &str, body: Option<&Value>) -> Result<String, MihomoRequestError> {
    request_mihomo_at(Path::new(MIHOMO_CONTROL_SOCKET), method, body).await
}

/** 读取 Mihomo 当前运行配置。 */
async fn read_mihomo_config() -> Result<Value, MihomoRequestError> {
    let response = request_mihomo("GET", None).await?;
    serde_json::from_str(&response)
        .map_err(|error| MihomoRequestError::Failed(format!("解析 Mihomo 配置失败: {error}")))
}

/** 判断指定读取失败在当前轮次之后是否需要重试。 */
fn should_retry_mihomo_read(attempt: usize, error: &MihomoRequestError) -> bool {
    error.is_unavailable() && attempt + 1 < MIHOMO_READ_ATTEMPTS
}

/** 有限重试读取 Mihomo 配置，吸收核心启动或重载的短暂竞态。 */
async fn read_mihomo_config_with_retry() -> Result<Value, MihomoRequestError> {
    for attempt in 0..MIHOMO_READ_ATTEMPTS {
        match read_mihomo_config().await {
            Ok(current) => return Ok(current),
            Err(error) if should_retry_mihomo_read(attempt, &error) => {
                tokio::time::sleep(MIHOMO_READ_RETRY_DELAY).await;
            }
            Err(error) => return Err(error),
        }
    }

    Err(MihomoRequestError::Failed(
        "读取 Mihomo 配置重试状态异常".to_string(),
    ))
}

/** 写入 Mihomo 出口与 TUN 配置，并校验运行态是否生效。 */
async fn patch_mihomo(interface_name: &str, tun: Value) -> Result<(), MihomoRequestError> {
    let payload = json!({
        "interface-name": interface_name,
        "tun": tun,
    });
    request_mihomo("PATCH", Some(&payload)).await?;

    let current = read_mihomo_config().await?;
    let current_interface = current
        .get("interface-name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if current_interface != interface_name {
        return Err(MihomoRequestError::Failed(format!(
            "Mihomo 公网出口校验失败，期望 {interface_name}，实际 {current_interface}"
        )));
    }

    Ok(())
}

/** 检测 Clash Verge Rev 的 Mihomo 核心是否仍在运行。 */
async fn is_verge_mihomo_running() -> Result<bool, String> {
    let status = tokio::process::Command::new("/usr/bin/pgrep")
        .args(["-x", "verge-mihomo"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|error| format!("无法检测 Mihomo 核心进程: {error}"))?;

    parse_pgrep_status(status.code())
}

/** 将 pgrep 退出状态转换为明确的进程存活结果。 */
fn parse_pgrep_status(exit_code: Option<i32>) -> Result<bool, String> {
    match exit_code {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        Some(code) => Err(format!("检测 Mihomo 核心进程失败，pgrep 退出码 {code}")),
        None => Err("检测 Mihomo 核心进程失败，pgrep 被信号终止".to_string()),
    }
}

/** 根据 Mihomo 核心状态决定连接失败能否安全降级。 */
fn handle_unavailable_mihomo(
    core_running: bool,
    error: MihomoRequestError,
) -> Result<Option<MihomoRouteState>, String> {
    let detail = match error {
        MihomoRequestError::Unavailable(message) => message,
        MihomoRequestError::Failed(message) => return Err(message),
    };
    if core_running {
        return Err(format!(
            "检测到 Mihomo 核心仍在运行，但控制接口不可用，请重启 Clash Verge Rev 后重试: {detail}"
        ));
    }

    eprintln!("[VPN][Fortinet] Mihomo 核心未运行，已跳过代理出口固定: {detail}");
    Ok(None)
}

/**
 * Fortinet 建立 PPP 前锁定 Mihomo 的公网物理出口。
 *
 * 未运行 Clash Verge Rev 时返回 `None`，不影响普通网络环境。
 */
pub async fn pin_mihomo_interface(
    physical_interface: &str,
) -> Result<Option<MihomoRouteState>, String> {
    if !Path::new(MIHOMO_CONTROL_SOCKET).exists() {
        return Ok(None);
    }

    let current = match read_mihomo_config_with_retry().await {
        Ok(current) => current,
        Err(error @ MihomoRequestError::Unavailable(_)) => {
            let core_running = is_verge_mihomo_running()
                .await
                .map_err(|process_error| format!("{}；同时{process_error}", error.message()))?;
            return handle_unavailable_mihomo(core_running, error);
        }
        Err(error) => return Err(error.into_message()),
    };
    let previous_tun = current.get("tun").cloned().unwrap_or_else(|| json!({}));
    let mut pinned_tun = previous_tun.clone();
    set_auto_detect_interface(&mut pinned_tun, false)?;

    let mut restored_tun = previous_tun;
    set_auto_detect_interface(&mut restored_tun, true)?;

    patch_mihomo(physical_interface, pinned_tun)
        .await
        .map_err(MihomoRequestError::into_message)?;
    Ok(Some(MihomoRouteState { tun: restored_tun }))
}

/** Fortinet 连接期间将 Mihomo 出口更新到最新物理主接口。 */
pub async fn follow_mihomo_interface(physical_interface: &str) -> Result<(), String> {
    if !Path::new(MIHOMO_CONTROL_SOCKET).exists() {
        return Ok(());
    }

    let current = read_mihomo_config()
        .await
        .map_err(MihomoRequestError::into_message)?;
    let current_interface = current
        .get("interface-name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut tun = current.get("tun").cloned().unwrap_or_else(|| json!({}));
    let auto_detect_enabled = tun
        .get("auto-detect-interface")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if current_interface == physical_interface && !auto_detect_enabled {
        return Ok(());
    }

    set_auto_detect_interface(&mut tun, false)?;
    patch_mihomo(physical_interface, tun)
        .await
        .map_err(MihomoRequestError::into_message)
}

/** 恢复 Mihomo 自动接口探测，避免断开后继续绑定已离线的流量或网线接口。 */
pub async fn restore_mihomo_interface(state: Option<MihomoRouteState>) {
    if !Path::new(MIHOMO_CONTROL_SOCKET).exists() {
        return;
    }

    let current = match read_mihomo_config().await {
        Ok(current) => current,
        Err(_) => return,
    };
    let current_interface = current
        .get("interface-name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let current_tun = current.get("tun").cloned().unwrap_or_else(|| json!({}));
    let auto_detect_enabled = current_tun
        .get("auto-detect-interface")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if state.is_none() && current_interface.is_empty() && auto_detect_enabled {
        return;
    }

    let mut tun = match state {
        Some(state) => state.tun,
        None => current_tun,
    };
    if set_auto_detect_interface(&mut tun, true).is_ok() {
        let _ = patch_mihomo("", tun).await;
    }
}

/** 应用启动时修复无 Fortinet 进程却残留的 Mihomo 静态出口。 */
pub async fn recover_stale_mihomo_interface() {
    if !Path::new(MIHOMO_CONTROL_SOCKET).exists() {
        return;
    }

    let fortinet_active = tokio::process::Command::new("pgrep")
        .args(["-x", "openfortivpn"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|status| status.success())
        .unwrap_or(false);
    if !fortinet_active {
        restore_mihomo_interface(None).await;
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    use super::request_mihomo_at;
    use super::{
        classify_mihomo_request_failure, handle_unavailable_mihomo, parse_pgrep_status,
        set_auto_detect_interface, should_retry_mihomo_read, MihomoRequestError,
        MIHOMO_READ_ATTEMPTS,
    };
    use serde_json::json;

    /** 确保 Mihomo TUN 配置可覆盖自动接口探测开关。 */
    #[test]
    fn updates_auto_detect_interface() {
        let mut tun = json!({ "enable": true, "auto-detect-interface": true });
        set_auto_detect_interface(&mut tun, false).expect("TUN 配置应可更新");

        assert_eq!(tun["auto-detect-interface"], false);
        assert_eq!(tun["enable"], true);
    }

    /** 确保断开 VPN 后可恢复自动接口探测。 */
    #[test]
    fn restores_auto_detect_interface() {
        let mut tun = json!({ "enable": true, "auto-detect-interface": false });
        set_auto_detect_interface(&mut tun, true).expect("TUN 配置应可恢复");

        assert_eq!(tun["auto-detect-interface"], true);
    }

    /** 确保 curl 连接失败与其它控制接口错误采用不同策略。 */
    #[test]
    fn classifies_mihomo_request_failures() {
        let unavailable = classify_mihomo_request_failure(
            Some(7),
            "curl: (7) Failed to connect to localhost port 80",
        );
        let rejected = classify_mihomo_request_failure(
            Some(22),
            "curl: (22) The requested URL returned error: 401",
        );

        assert!(matches!(unavailable, MihomoRequestError::Unavailable(_)));
        assert!(matches!(rejected, MihomoRequestError::Failed(_)));
    }

    /** 确保只有尚未耗尽次数的连接失败才会重试。 */
    #[test]
    fn retries_only_transient_connection_failures() {
        let unavailable = MihomoRequestError::Unavailable("暂时不可连接".to_string());
        let failed = MihomoRequestError::Failed("接口拒绝请求".to_string());

        assert!(should_retry_mihomo_read(0, &unavailable));
        assert!(should_retry_mihomo_read(1, &unavailable));
        assert!(!should_retry_mihomo_read(
            MIHOMO_READ_ATTEMPTS - 1,
            &unavailable
        ));
        assert!(!should_retry_mihomo_read(0, &failed));
    }

    /** 确保仅在 Mihomo 核心明确未运行时降级。 */
    #[test]
    fn degrades_only_when_mihomo_core_is_not_running() {
        let skipped = handle_unavailable_mihomo(
            false,
            MihomoRequestError::Unavailable("残留套接字".to_string()),
        );
        let blocked = handle_unavailable_mihomo(
            true,
            MihomoRequestError::Unavailable("控制接口异常".to_string()),
        );
        let rejected = handle_unavailable_mihomo(
            false,
            MihomoRequestError::Failed("控制接口返回 401".to_string()),
        );

        assert!(matches!(skipped, Ok(None)));
        let blocked_error = match blocked {
            Err(error) => error,
            Ok(_) => panic!("活动核心的控制接口异常应阻止连接"),
        };
        let rejected_error = match rejected {
            Err(error) => error,
            Ok(_) => panic!("非连接错误不得降级"),
        };
        assert!(blocked_error.contains("请重启 Clash Verge Rev"));
        assert_eq!(rejected_error, "控制接口返回 401");
    }

    /** 确保进程检测只有退出码 1 被视为核心未运行。 */
    #[test]
    fn parses_pgrep_status_conservatively() {
        assert_eq!(parse_pgrep_status(Some(0)), Ok(true));
        assert_eq!(parse_pgrep_status(Some(1)), Ok(false));
        assert!(parse_pgrep_status(Some(2)).is_err());
        assert!(parse_pgrep_status(None).is_err());
    }

    /** 确保 macOS 上无监听的残留 Unix Socket 被识别为不可连接。 */
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn classifies_stale_unix_socket_as_unavailable() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("系统时间应晚于 Unix 纪元")
            .as_nanos();
        let socket_path = std::env::temp_dir().join(format!(
            "yuyan-vpn-stale-mihomo-{}-{unique}.sock",
            std::process::id()
        ));
        let listener =
            tokio::net::UnixListener::bind(&socket_path).expect("应能创建临时 Mihomo Unix Socket");
        drop(listener);

        let result = request_mihomo_at(&socket_path, "GET", None).await;
        let _ = std::fs::remove_file(&socket_path);

        assert!(matches!(result, Err(MihomoRequestError::Unavailable(_))));
    }
}
