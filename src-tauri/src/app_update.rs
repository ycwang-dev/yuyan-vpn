use crate::vpn::{self, VpnManager};
use tauri::{AppHandle, State};

/** 更新安装前清理 VPN 的最长等待时间。 */
const UPDATE_PREPARE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/**
 * 在安装更新前安全停止全部 VPN 与网络守护任务。
 *
 * 清理成功后保持 `shutting_down` 门禁，防止更新安装和重启之间又建立新隧道；
 * 清理失败或超时时恢复门禁，由前端阻止本次安装并展示错误。
 */
#[tauri::command]
pub async fn prepare_app_update_install(
    app: AppHandle,
    manager: State<'_, VpnManager>,
) -> Result<(), String> {
    let result = tokio::time::timeout(
        UPDATE_PREPARE_TIMEOUT,
        vpn::shutdown::shutdown_all_vpns(&app, manager.inner()),
    )
    .await;

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            manager.cancel_shutdown();
            Err(format!("更新安装前的 VPN 清理失败：{error}"))
        }
        Err(_) => {
            manager.cancel_shutdown();
            Err("更新安装前的 VPN 清理超过 20 秒，已取消安装".to_string())
        }
    }
}

/** 更新安装失败后恢复 VPN 连接门禁，允许用户继续使用当前版本。 */
#[tauri::command]
pub fn cancel_app_update_install_preparation(manager: State<'_, VpnManager>) {
    manager.cancel_shutdown();
}
