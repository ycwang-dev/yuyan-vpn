use std::process::Command;
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};
use tauri::image::Image;
use tauri::{Emitter, Manager};

mod app_update;
mod vpn;

/** 暗色主题下的 App Dock 图标字节（已更新为全新的 C4D 液态玻璃图标且优化尺寸边距） */
const DARK_ICON: &[u8] = include_bytes!("../resources/yuyan_dark_clean.png");
/** 亮色主题下的 App Dock 图标字节（已更新为全新的 C4D 液态玻璃图标且优化尺寸边距） */
const LIGHT_ICON: &[u8] = include_bytes!("../resources/yuyan_light_clean.png");

/** 尚未开始安全退出。 */
const EXIT_PHASE_IDLE: u8 = 0;
/** 正在清理 VPN 与网络资源。 */
const EXIT_PHASE_CLEANING: u8 = 1;
/** 清理已完成，下一次退出事件可真正结束进程。 */
const EXIT_PHASE_READY: u8 = 2;

/** 协调重复退出事件，保证清理只执行一次且清理完成前不会结束 App。 */
#[derive(Clone, Default)]
struct SafeExitCoordinator {
    phase: Arc<AtomicU8>,
}

impl SafeExitCoordinator {
    /** 尝试取得本次安全退出清理的执行权。 */
    fn try_begin(&self) -> bool {
        self.phase
            .compare_exchange(
                EXIT_PHASE_IDLE,
                EXIT_PHASE_CLEANING,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    }

    /** 判断 VPN 清理是否已经通过最终验收。 */
    fn is_ready(&self) -> bool {
        self.phase.load(Ordering::SeqCst) == EXIT_PHASE_READY
    }

    /** 标记清理成功，允许随后触发的退出事件结束 App。 */
    fn mark_ready(&self) {
        self.phase.store(EXIT_PHASE_READY, Ordering::SeqCst);
    }

    /** 清理失败后恢复空闲态，允许用户处理问题并再次退出。 */
    fn reset(&self) {
        self.phase.store(EXIT_PHASE_IDLE, Ordering::SeqCst);
    }
}

#[tauri::command]
fn change_app_icon(app_handle: tauri::AppHandle, is_dark: bool) -> Result<(), String> {
    let icon_bytes = if is_dark { DARK_ICON } else { LIGHT_ICON };

    #[cfg(target_os = "macos")]
    {
        set_macos_dock_icon(icon_bytes);
    }

    let img = Image::from_bytes(icon_bytes).map_err(|e| e.to_string())?;
    for window in app_handle.webview_windows().values() {
        let _ = window.set_icon(img.clone());
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn set_macos_dock_icon(png_bytes: &[u8]) {
    use cocoa::base::id;
    use objc::{msg_send, sel, sel_impl};

    unsafe {
        let ns_data: id = msg_send![objc::class!(NSData), dataWithBytes: png_bytes.as_ptr() length: png_bytes.len()];
        let ns_image_alloc: id = msg_send![objc::class!(NSImage), alloc];
        let ns_image: id = msg_send![ns_image_alloc, initWithData: ns_data];
        let shared_app: id = msg_send![objc::class!(NSApplication), sharedApplication];
        let _: () = msg_send![shared_app, setApplicationIconImage: ns_image];
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemInfo {
    app_version: String,
    tauri_version: String,
    os_info: String,
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[allow(non_snake_case)]
struct RtlOsVersionInfoW {
    dwOSVersionInfoSize: u32,
    dwMajorVersion: u32,
    dwMinorVersion: u32,
    dwBuildNumber: u32,
    dwPlatformId: u32,
    szCSDVersion: [u16; 128],
}

#[cfg(target_os = "windows")]
#[link(name = "ntdll")]
extern "system" {
    fn RtlGetVersion(version_info: *mut RtlOsVersionInfoW) -> i32;
}

#[cfg(target_os = "windows")]
fn get_windows_version_label() -> String {
    let mut version_info = RtlOsVersionInfoW {
        dwOSVersionInfoSize: std::mem::size_of::<RtlOsVersionInfoW>() as u32,
        dwMajorVersion: 0,
        dwMinorVersion: 0,
        dwBuildNumber: 0,
        dwPlatformId: 0,
        szCSDVersion: [0; 128],
    };

    let status = unsafe { RtlGetVersion(&mut version_info) };
    if status >= 0 {
        format!(
            "Windows {}.{}.{}",
            version_info.dwMajorVersion, version_info.dwMinorVersion, version_info.dwBuildNumber
        )
    } else {
        "Windows Unknown".to_string()
    }
}

#[tauri::command]
fn get_system_info(app_handle: tauri::AppHandle) -> SystemInfo {
    let app_version = app_handle.package_info().version.to_string();

    #[cfg(target_os = "macos")]
    let os_version = Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "Unknown".to_string());

    #[cfg(target_os = "windows")]
    let os_version = get_windows_version_label();

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let os_version = "Unknown".to_string();

    let os_info = format!(
        "{} ({} {})",
        os_version,
        std::env::consts::OS,
        std::env::consts::ARCH
    );

    SystemInfo {
        app_version,
        tauri_version: tauri::VERSION.to_string(),
        os_info,
    }
}

#[tauri::command]
fn exit_app(app: tauri::AppHandle) {
    println!("🛑 收到退出指令，开始执行 VPN 安全清理...");
    app.exit(0);
}

#[tauri::command]
fn reveal_in_file_manager(path: String) -> Result<(), String> {
    println!("🔍 正在打开文件管理器定位文件: {}", path);
    #[cfg(target_os = "windows")]
    {
        Command::new("explorer.exe")
            .arg("/select,")
            .arg(&path)
            .spawn()
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg("-R")
            .arg(&path)
            .spawn()
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        if let Some(parent) = std::path::Path::new(&path).parent() {
            Command::new("xdg-open")
                .arg(parent)
                .spawn()
                .map(|_| ())
                .map_err(|e| e.to_string())
        } else {
            Err("无效路径".to_string())
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let vpn_manager = vpn::VpnManager::new();
    let safe_exit_manager = vpn_manager.clone();
    let safe_exit_coordinator = SafeExitCoordinator::default();
    #[cfg(target_os = "macos")]
    let network_recovery_manager = vpn_manager.clone();

    tauri::Builder::default()
        .manage(vpn_manager.clone())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .invoke_handler(tauri::generate_handler![
            change_app_icon,
            app_update::prepare_app_update_install,
            app_update::cancel_app_update_install_preparation,
            exit_app,
            reveal_in_file_manager,
            get_system_info,
            vpn::save_vpn_config,
            vpn::load_vpn_config,
            vpn::verify_sudo_password,
            vpn::has_sudo_credentials,
            vpn::get_vpn_state,
            vpn::atrust::connect_atrust,
            vpn::atrust::disconnect_atrust,
            vpn::fortinet::connect_fortinet,
            vpn::fortinet::disconnect_fortinet,
            vpn::submit_vpn_mfa
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                #[cfg(target_os = "macos")]
                {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .on_menu_event(|app_handle, event| {
            let event_id = event.id().as_ref();
            if event_id == "check-update" {
                let _ = app_handle.emit("menu-check-update", ());
            } else if event_id == "about-yuyan" {
                let _ = app_handle.emit("menu-about", ());
            }
        })
        .setup(move |app| {
            #[cfg(target_os = "macos")]
            tauri::async_runtime::spawn(vpn::maintain_idle_network_state(network_recovery_manager));

            #[cfg(target_os = "macos")]
            {
                use tauri::menu::{Menu, MenuItemBuilder};
                let app_handle = app.handle();
                if let Ok(menu) = Menu::default(app_handle) {
                    if let Ok(items) = menu.items() {
                        if let Some(first_item) = items.first() {
                            if let Some(app_submenu) = first_item.as_submenu() {
                                let _ = app_submenu.remove_at(0);
                                if let Ok(about_item) = MenuItemBuilder::new("关于雨燕 SwiftVPN")
                                    .id("about-yuyan")
                                    .build(app_handle)
                                {
                                    let _ = app_submenu.insert(&about_item, 0);
                                }

                                if let Ok(check_update_item) = MenuItemBuilder::new("检查更新")
                                    .id("check-update")
                                    .build(app_handle)
                                {
                                    let _ = app_submenu.insert(&check_update_item, 1);
                                }
                            }
                        }
                    }
                    let _ = app.set_menu(menu);
                }
            }

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(move |app_handle, event| match event {
            tauri::RunEvent::ExitRequested { api, code, .. } => {
                if safe_exit_coordinator.is_ready() {
                    return;
                }

                api.prevent_exit();
                if !safe_exit_coordinator.try_begin() {
                    return;
                }

                let cleanup_app = app_handle.clone();
                let cleanup_manager = safe_exit_manager.clone();
                let cleanup_coordinator = safe_exit_coordinator.clone();
                tauri::async_runtime::spawn(async move {
                    let cleanup_result = tokio::time::timeout(
                        std::time::Duration::from_secs(20),
                        vpn::shutdown::shutdown_all_vpns(&cleanup_app, &cleanup_manager),
                    )
                    .await;

                    match cleanup_result {
                        Ok(Ok(())) => {
                            cleanup_coordinator.mark_ready();
                            cleanup_app.exit(code.unwrap_or(0));
                        }
                        Ok(Err(error)) => {
                            eprintln!("安全退出清理失败，已阻止 App 退出：{error}");
                            let _ = cleanup_app.emit(
                                "app-exit-cleanup-status",
                                vpn::shutdown::ShutdownStatusPayload {
                                    success: false,
                                    message: error,
                                },
                            );
                            cleanup_manager.cancel_shutdown();
                            cleanup_coordinator.reset();
                            if let Some(window) = cleanup_app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.unminimize();
                                let _ = window.set_focus();
                            }
                        }
                        Err(_) => {
                            let message = "VPN 安全清理超过 20 秒，已阻止 App 退出";
                            eprintln!("{message}");
                            let _ = cleanup_app.emit(
                                "app-exit-cleanup-status",
                                vpn::shutdown::ShutdownStatusPayload {
                                    success: false,
                                    message: message.to_string(),
                                },
                            );
                            cleanup_manager.cancel_shutdown();
                            cleanup_coordinator.reset();
                            if let Some(window) = cleanup_app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.unminimize();
                                let _ = window.set_focus();
                            }
                        }
                    }
                });
            }
            #[cfg(target_os = "macos")]
            tauri::RunEvent::Reopen {
                has_visible_windows,
                ..
            } => {
                if !has_visible_windows {
                    if let Some(window) = app_handle.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
            }
            _ => {}
        });
}
