use super::{atrust, fortinet, VpnManager, VpnStatus};
use tauri::{AppHandle, Emitter};

/** 安全退出清理状态，供前端显示失败原因。 */
#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShutdownStatusPayload {
    pub success: bool,
    pub message: String,
}

/** 判断指定 VPN 引擎进程是否仍存在。 */
#[cfg(target_os = "macos")]
async fn process_exists(process_name: &str) -> bool {
    tokio::process::Command::new("pgrep")
        .args(["-x", process_name])
        .status()
        .await
        .map(|status| status.success())
        .unwrap_or(false)
}

/** 使用 tasklist 复核 Windows 本机是否仍有指定 VPN 引擎。 */
#[cfg(target_os = "windows")]
async fn process_exists(process_name: &str) -> bool {
    let image_name = format!("{process_name}.exe");
    tokio::process::Command::new("tasklist.exe")
        .args([
            "/FI",
            &format!("IMAGENAME eq {image_name}"),
            "/FO",
            "CSV",
            "/NH",
        ])
        .output()
        .await
        .map(|output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout)
                    .to_ascii_lowercase()
                    .contains(&image_name.to_ascii_lowercase())
        })
        .unwrap_or(false)
}

/** 其他未支持平台不执行进程探测。 */
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
async fn process_exists(_process_name: &str) -> bool {
    false
}

/** 等待两个 VPN 引擎完全退出，避免 sudo 包装进程晚于主进程结束。 */
async fn wait_for_sidecars_to_exit() -> Result<(), String> {
    for _ in 0..30 {
        let (fortinet_exists, atrust_exists) = tokio::join!(
            process_exists("openfortivpn"),
            process_exists("zju-connect")
        );
        if !fortinet_exists && !atrust_exists {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let mut residual_processes = Vec::new();
    if process_exists("openfortivpn").await {
        residual_processes.push("openfortivpn");
    }
    if process_exists("zju-connect").await {
        residual_processes.push("zju-connect");
    }
    Err(format!(
        "VPN 进程未完全退出：{}",
        residual_processes.join(", ")
    ))
}

/** 在没有 sudo 凭据且系统无残留引擎时，回收本地任务与临时文件。 */
async fn cleanup_local_resources(manager: &VpnManager) {
    let (
        mut fortinet_child,
        fortinet_watcher,
        fortinet_network_watcher,
        mut atrust_child,
        atrust_watcher,
        atrust_readiness_watcher,
        fortinet_config_path,
        atrust_fifo_path,
    ) = {
        let mut inner = manager.inner.lock().await;
        inner.fortinet_status = VpnStatus::Disconnected;
        inner.fortinet_ip = None;
        inner.fortinet_start_time = None;
        inner.atrust_status = VpnStatus::Disconnected;
        inner.atrust_ip = None;
        inner.atrust_start_time = None;
        inner.atrust_stdin = None;
        inner.atrust_interface = None;
        inner.atrust_route_ready = false;
        inner.atrust_stack_ready = false;
        (
            inner.fortinet_child.take(),
            inner.fortinet_watcher.take(),
            inner.fortinet_network_watcher.take(),
            inner.atrust_child.take(),
            inner.atrust_watcher.take(),
            inner.atrust_readiness_watcher.take(),
            inner.fortinet_config_path.take(),
            inner.atrust_fifo_path.take(),
        )
    };

    if let Some(watcher) = fortinet_watcher {
        watcher.abort();
    }
    if let Some(watcher) = fortinet_network_watcher {
        watcher.abort();
    }
    if let Some(watcher) = atrust_watcher {
        watcher.abort();
    }
    if let Some(watcher) = atrust_readiness_watcher {
        watcher.abort();
    }
    if let Some(child) = fortinet_child.as_mut() {
        let _ = child.kill().await;
    }
    if let Some(child) = atrust_child.as_mut() {
        let _ = child.kill().await;
    }
    if let Some(path) = fortinet_config_path {
        let _ = tokio::fs::remove_file(path).await;
    }
    if let Some(path) = atrust_fifo_path {
        let _ = tokio::fs::remove_file(path).await;
    }
}

/**
 * 安全停止全部 VPN。
 *
 * 该函数供真正退出入口复用：先阻止新连接，再清理两个特权 sidecar、后台任务与临时文件，
 * 最后复核系统中没有残留引擎。任一步失败都返回错误，由调用方阻止 App 退出。
 */
pub async fn shutdown_all_vpns(app_handle: &AppHandle, manager: &VpnManager) -> Result<(), String> {
    manager.begin_shutdown();

    #[cfg(target_os = "windows")]
    {
        super::windows::shutdown_helper(app_handle, manager).await?;
        let _ = app_handle.emit(
            "app-exit-cleanup-status",
            ShutdownStatusPayload {
                success: true,
                message: "本 App 托管的 Windows VPN 进程、Wintun 与分流路由已清理".to_string(),
            },
        );
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
        let has_sudo_credentials = manager.inner.lock().await.sudo_password.is_some();

        if has_sudo_credentials {
            let (fortinet_result, atrust_result) = tokio::join!(
                fortinet::disconnect_fortinet_managed(app_handle, manager),
                atrust::disconnect_atrust_managed(app_handle, manager)
            );
            let mut errors = Vec::new();
            if let Err(error) = fortinet_result {
                errors.push(format!("Fortinet 清理失败：{error}"));
            }
            if let Err(error) = atrust_result {
                errors.push(format!("aTrust 清理失败：{error}"));
            }
            if !errors.is_empty() {
                let message = errors.join("；");
                let _ = app_handle.emit(
                    "app-exit-cleanup-status",
                    ShutdownStatusPayload {
                        success: false,
                        message: message.clone(),
                    },
                );
                return Err(message);
            }
        } else {
            cleanup_local_resources(manager).await;
        }

        wait_for_sidecars_to_exit().await?;
        let _ = app_handle.emit(
            "app-exit-cleanup-status",
            ShutdownStatusPayload {
                success: true,
                message: "VPN 进程与临时网络资源已清理".to_string(),
            },
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ShutdownStatusPayload;

    /** 确保退出状态事件保持前端约定的 camelCase 字段。 */
    #[test]
    fn serializes_shutdown_payload() {
        let value = serde_json::to_value(ShutdownStatusPayload {
            success: false,
            message: "清理失败".to_string(),
        })
        .expect("payload should serialize");
        assert_eq!(value["success"], false);
        assert_eq!(value["message"], "清理失败");
    }
}
