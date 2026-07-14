use serde_json::{json, Value};
use std::path::Path;
use std::process::Stdio;

/** Clash Verge Rev 默认的 Mihomo 控制套接字。 */
const MIHOMO_CONTROL_SOCKET: &str = "/tmp/verge/verge-mihomo.sock";

/** Fortinet 连接前保存的 Mihomo 出口状态。 */
#[derive(Clone)]
pub struct MihomoRouteState {
    tun: Value,
}

/** 修改 Mihomo TUN 的自动接口探测开关。 */
fn set_auto_detect_interface(tun: &mut Value, enabled: bool) -> Result<(), String> {
    let tun_object = tun.as_object_mut().ok_or("Mihomo TUN 配置格式无效")?;
    tun_object.insert("auto-detect-interface".to_string(), Value::Bool(enabled));
    Ok(())
}

/** 通过本机 Unix Socket 调用 Mihomo 控制接口。 */
async fn request_mihomo(method: &str, body: Option<&Value>) -> Result<String, String> {
    let mut command = tokio::process::Command::new("/usr/bin/curl");
    command
        .arg("--silent")
        .arg("--show-error")
        .arg("--fail-with-body")
        .arg("--unix-socket")
        .arg(MIHOMO_CONTROL_SOCKET)
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

    let output = command
        .output()
        .await
        .map_err(|error| format!("无法调用 Mihomo 控制接口: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "Mihomo 控制接口返回失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/** 读取 Mihomo 当前运行配置。 */
async fn read_mihomo_config() -> Result<Value, String> {
    let response = request_mihomo("GET", None).await?;
    serde_json::from_str(&response).map_err(|error| format!("解析 Mihomo 配置失败: {error}"))
}

/** 写入 Mihomo 出口与 TUN 配置，并校验运行态是否生效。 */
async fn patch_mihomo(interface_name: &str, tun: Value) -> Result<(), String> {
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
        return Err(format!(
            "Mihomo 公网出口校验失败，期望 {interface_name}，实际 {current_interface}"
        ));
    }

    Ok(())
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

    let current = read_mihomo_config().await?;
    let previous_tun = current.get("tun").cloned().unwrap_or_else(|| json!({}));
    let mut pinned_tun = previous_tun.clone();
    set_auto_detect_interface(&mut pinned_tun, false)?;

    let mut restored_tun = previous_tun;
    set_auto_detect_interface(&mut restored_tun, true)?;

    patch_mihomo(physical_interface, pinned_tun).await?;
    Ok(Some(MihomoRouteState { tun: restored_tun }))
}

/** Fortinet 连接期间将 Mihomo 出口更新到最新物理主接口。 */
pub async fn follow_mihomo_interface(physical_interface: &str) -> Result<(), String> {
    if !Path::new(MIHOMO_CONTROL_SOCKET).exists() {
        return Ok(());
    }

    let current = read_mihomo_config().await?;
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
    patch_mihomo(physical_interface, tun).await
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
    use super::set_auto_detect_interface;
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
}
