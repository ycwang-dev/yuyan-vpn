use crate::vpn::{self, VpnManager, VpnStatus, VpnType};
use serde::Serialize;
use tauri::image::Image;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
#[cfg(target_os = "windows")]
use tauri::tray::{MouseButton, MouseButtonState, TrayIconEvent};
use tauri::{App, AppHandle, Emitter, Manager};
use tauri_plugin_autostart::ManagerExt;

/** 主托盘图标的稳定标识。 */
const TRAY_ID: &str = "yuyan-main-tray";
/** 托盘菜单项标识：北京 VPN。 */
const MENU_FORTINET: &str = "tray-toggle-fortinet";
/** 托盘菜单项标识：长沙 VPN。 */
const MENU_ATRUST: &str = "tray-toggle-atrust";
/** 托盘菜单项标识：连接全部 VPN。 */
const MENU_CONNECT_ALL: &str = "tray-connect-all";
/** 托盘菜单项标识：断开全部 VPN。 */
const MENU_DISCONNECT_ALL: &str = "tray-disconnect-all";
/** 托盘菜单项标识：打开控制中心。 */
const MENU_OPEN_DASHBOARD: &str = "tray-open-dashboard";
/** 托盘菜单项标识：打开登录设置。 */
const MENU_OPEN_SETTINGS: &str = "tray-open-settings";
/** 托盘菜单项标识：打开连接日志。 */
const MENU_OPEN_CONSOLE: &str = "tray-open-console";
/** 托盘菜单项标识：开机启动。 */
const MENU_AUTOSTART: &str = "tray-autostart";
/** 托盘菜单项标识：检查更新。 */
const MENU_CHECK_UPDATE: &str = "tray-check-update";
/** 托盘菜单项标识：安全退出。 */
const MENU_QUIT: &str = "tray-quit";

/** 托盘断开状态图标。 */
const ICON_DISCONNECTED: &[u8] = include_bytes!("../icons/tray/disconnected.png");
/** 托盘部分连接状态图标。 */
const ICON_PARTIAL: &[u8] = include_bytes!("../icons/tray/partial.png");
/** 托盘全部连接状态图标。 */
const ICON_CONNECTED: &[u8] = include_bytes!("../icons/tray/connected.png");
/** 托盘错误或待验证状态图标。 */
const ICON_ATTENTION: &[u8] = include_bytes!("../icons/tray/attention.png");
/** macOS 使用系统模板色渲染雨燕图标，自动适配浅色与深色菜单栏。 */
const ICON_AS_TEMPLATE: bool = cfg!(target_os = "macos");

/** 托盘连接动作，值与前端全局事件约定保持一致。 */
#[derive(Clone, Copy)]
enum TrayVpnAction {
    Fortinet,
    Atrust,
    Both,
    DisconnectAll,
}

impl TrayVpnAction {
    /** 返回前端事件使用的稳定字符串。 */
    fn as_str(self) -> &'static str {
        match self {
            Self::Fortinet => "fortinet",
            Self::Atrust => "atrust",
            Self::Both => "both",
            Self::DisconnectAll => "disconnectAll",
        }
    }
}

/** 托盘聚合视觉状态。 */
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TrayVisualState {
    Disconnected,
    Partial,
    Connected,
    Attention,
}

/** 单条 VPN 的托盘快照。 */
#[derive(Clone, Debug, PartialEq, Eq)]
struct TrayVpnSnapshot {
    status: VpnStatus,
    virtual_ip: Option<String>,
    uptime: u64,
}

/** 两条 VPN 的托盘聚合快照。 */
#[derive(Clone, Debug, PartialEq, Eq)]
struct TraySnapshot {
    fortinet: TrayVpnSnapshot,
    atrust: TrayVpnSnapshot,
}

/** 前端导航事件载荷。 */
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TrayNavigationPayload {
    path: String,
}

/** 需要主界面继续处理的托盘动作载荷。 */
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TrayActionRequiredPayload {
    action: String,
    reason: String,
    message: String,
    path: String,
}

/** 托盘异步操作反馈载荷。 */
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TrayFeedbackPayload {
    level: String,
    message: String,
}

/** 保存可动态更新的原生托盘菜单项。 */
pub struct TrayController {
    summary: MenuItem<tauri::Wry>,
    fortinet: CheckMenuItem<tauri::Wry>,
    atrust: CheckMenuItem<tauri::Wry>,
    connect_all: MenuItem<tauri::Wry>,
    disconnect_all: MenuItem<tauri::Wry>,
    autostart: CheckMenuItem<tauri::Wry>,
    visual_state: std::sync::Mutex<TrayVisualState>,
}

impl TrayController {
    /** 根据最新 VPN 快照更新菜单、Tooltip 和托盘图标。 */
    fn apply_snapshot(&self, app_handle: &AppHandle, snapshot: &TraySnapshot) {
        let connected_count = [snapshot.fortinet.status, snapshot.atrust.status]
            .into_iter()
            .filter(|status| *status == VpnStatus::Connected)
            .count();
        let has_transition = [snapshot.fortinet.status, snapshot.atrust.status]
            .into_iter()
            .any(is_transition_status);
        let all_active = [snapshot.fortinet.status, snapshot.atrust.status]
            .into_iter()
            .all(is_active_status);
        let any_active = [snapshot.fortinet.status, snapshot.atrust.status]
            .into_iter()
            .any(is_active_status);

        let _ = self
            .summary
            .set_text(format!("雨燕 SwiftVPN · {connected_count}/2 已连接"));
        update_vpn_menu_item(&self.fortinet, "北京 VPN", &snapshot.fortinet);
        update_vpn_menu_item(&self.atrust, "长沙 VPN", &snapshot.atrust);
        let _ = self.connect_all.set_enabled(!all_active && !has_transition);
        let _ = self
            .disconnect_all
            .set_enabled(any_active && !has_transition);

        if let Some(tray_icon) = app_handle.tray_by_id(TRAY_ID) {
            let visual_state = resolve_visual_state(snapshot);
            let icon_changed = self
                .visual_state
                .lock()
                .map(|current| *current != visual_state)
                .unwrap_or(true);
            if icon_changed {
                if let Ok(icon) = load_tray_icon(visual_state) {
                    if tray_icon
                        .set_icon_with_as_template(Some(icon), ICON_AS_TEMPLATE)
                        .is_ok()
                    {
                        if let Ok(mut current) = self.visual_state.lock() {
                            *current = visual_state;
                        }
                    }
                }
            }
            let _ = tray_icon.set_tooltip(Some(build_tooltip(snapshot)));
        }
    }
}

/** 创建原生托盘菜单并注册到 Tauri 应用。 */
pub fn setup(app: &mut App) -> Result<(), Box<dyn std::error::Error>> {
    let summary = MenuItem::with_id(
        app,
        "tray-summary",
        "雨燕 SwiftVPN · 0/2 已连接",
        false,
        None::<&str>,
    )?;
    let fortinet = CheckMenuItem::with_id(
        app,
        MENU_FORTINET,
        "北京 VPN · 未连接",
        true,
        false,
        None::<&str>,
    )?;
    let atrust = CheckMenuItem::with_id(
        app,
        MENU_ATRUST,
        "长沙 VPN · 未连接",
        true,
        false,
        None::<&str>,
    )?;
    let connect_all = MenuItem::with_id(app, MENU_CONNECT_ALL, "连接全部 VPN", true, None::<&str>)?;
    let disconnect_all = MenuItem::with_id(
        app,
        MENU_DISCONNECT_ALL,
        "断开全部 VPN",
        false,
        None::<&str>,
    )?;
    let open_dashboard = MenuItem::with_id(
        app,
        MENU_OPEN_DASHBOARD,
        "打开 VPN 控制中心",
        true,
        None::<&str>,
    )?;
    let open_settings =
        MenuItem::with_id(app, MENU_OPEN_SETTINGS, "打开登录设置…", true, None::<&str>)?;
    let open_console =
        MenuItem::with_id(app, MENU_OPEN_CONSOLE, "查看连接日志", true, None::<&str>)?;
    let autostart_enabled = app.autolaunch().is_enabled().unwrap_or(false);
    let autostart = CheckMenuItem::with_id(
        app,
        MENU_AUTOSTART,
        "开机启动（后台运行）",
        true,
        autostart_enabled,
        None::<&str>,
    )?;
    let check_update = MenuItem::with_id(app, MENU_CHECK_UPDATE, "检查更新", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, MENU_QUIT, "退出雨燕（将断开 VPN）", true, None::<&str>)?;
    let separator_primary = PredefinedMenuItem::separator(app)?;
    let separator_secondary = PredefinedMenuItem::separator(app)?;
    let separator_quit = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(
        app,
        &[
            &summary,
            &fortinet,
            &atrust,
            &separator_primary,
            &connect_all,
            &disconnect_all,
            &separator_secondary,
            &open_dashboard,
            &open_settings,
            &open_console,
            &autostart,
            &check_update,
            &separator_quit,
            &quit,
        ],
    )?;

    let initial_icon = load_tray_icon(TrayVisualState::Disconnected)?;
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(initial_icon)
        .icon_as_template(ICON_AS_TEMPLATE)
        .tooltip("雨燕 SwiftVPN\n北京：未连接\n长沙：未连接")
        .menu(&menu)
        .show_menu_on_left_click(cfg!(target_os = "macos"))
        .on_tray_icon_event(|tray, event| {
            #[cfg(target_os = "windows")]
            if matches!(
                event,
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } | TrayIconEvent::DoubleClick {
                    button: MouseButton::Left,
                    ..
                }
            ) {
                show_main_window(tray.app_handle());
                emit_navigation(tray.app_handle(), "/dashboard");
            }
            #[cfg(not(target_os = "windows"))]
            let _ = (tray, event);
        })
        .build(app)?;

    let controller = TrayController {
        summary,
        fortinet,
        atrust,
        connect_all,
        disconnect_all,
        autostart,
        visual_state: std::sync::Mutex::new(TrayVisualState::Disconnected),
    };
    if !app.manage(controller) {
        return Err("托盘控制器状态重复注册".into());
    }

    let app_handle = app.handle().clone();
    let manager = app.state::<VpnManager>().inner().clone();
    tauri::async_runtime::spawn(sync_loop(app_handle, manager));
    Ok(())
}

/** 处理应用菜单或托盘菜单事件，返回事件是否已经消费。 */
pub fn handle_menu_event(app_handle: &AppHandle, event_id: &str) -> bool {
    match event_id {
        MENU_FORTINET => spawn_toggle(app_handle, VpnType::Fortinet),
        MENU_ATRUST => spawn_toggle(app_handle, VpnType::Atrust),
        MENU_CONNECT_ALL => spawn_connect_all(app_handle),
        MENU_DISCONNECT_ALL => spawn_disconnect_all(app_handle),
        MENU_OPEN_DASHBOARD => {
            show_main_window(app_handle);
            emit_navigation(app_handle, "/dashboard");
        }
        MENU_OPEN_SETTINGS => {
            show_main_window(app_handle);
            emit_navigation(app_handle, "/settings");
        }
        MENU_OPEN_CONSOLE => {
            show_main_window(app_handle);
            emit_navigation(app_handle, "/console");
        }
        MENU_AUTOSTART => toggle_autostart(app_handle),
        MENU_CHECK_UPDATE => {
            show_main_window(app_handle);
            let _ = app_handle.emit("menu-check-update", ());
        }
        MENU_QUIT => app_handle.exit(0),
        _ => return false,
    }
    true
}

/** 显示、恢复并聚焦主窗口。 */
pub fn show_main_window(app_handle: &AppHandle) {
    if let Some(window) = app_handle.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/** 返回启动参数是否要求应用只在托盘后台启动。 */
pub fn should_start_hidden() -> bool {
    std::env::args().any(|argument| argument == "--hidden")
}

/** 后台刷新 Windows helper 状态并同步原生托盘。 */
async fn sync_loop(app_handle: AppHandle, manager: VpnManager) {
    loop {
        #[cfg(target_os = "windows")]
        if let Err(error) = vpn::windows::refresh(&app_handle, &manager).await {
            eprintln!("托盘刷新 Windows VPN 状态失败：{error}");
        }

        let snapshot = read_snapshot(&manager).await;
        if let Some(controller) = app_handle.try_state::<TrayController>() {
            controller.apply_snapshot(&app_handle, &snapshot);
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

/** 读取两条 VPN 的轻量托盘状态快照。 */
async fn read_snapshot(manager: &VpnManager) -> TraySnapshot {
    let inner = manager.inner.lock().await;
    TraySnapshot {
        fortinet: TrayVpnSnapshot {
            status: inner.fortinet_status,
            virtual_ip: inner.fortinet_ip.clone(),
            uptime: inner
                .fortinet_start_time
                .map(|started_at| started_at.elapsed().as_secs())
                .unwrap_or_default(),
        },
        atrust: TrayVpnSnapshot {
            status: inner.atrust_status,
            virtual_ip: inner.atrust_ip.clone(),
            uptime: inner
                .atrust_start_time
                .map(|started_at| started_at.elapsed().as_secs())
                .unwrap_or_default(),
        },
    }
}

/** 更新单条 VPN 的复选菜单项。 */
fn update_vpn_menu_item(item: &CheckMenuItem<tauri::Wry>, label: &str, snapshot: &TrayVpnSnapshot) {
    let _ = item.set_text(format!("{label} · {}", status_label(snapshot.status)));
    let _ = item.set_checked(snapshot.status == VpnStatus::Connected);
    let _ = item.set_enabled(!is_transition_status(snapshot.status));
}

/** 根据 VPN 状态返回紧凑中文标签。 */
fn status_label(status: VpnStatus) -> &'static str {
    match status {
        VpnStatus::Disconnected => "未连接",
        VpnStatus::Connecting => "正在连接…",
        VpnStatus::Authenticating => "需要验证…",
        VpnStatus::Connected => "已连接",
        VpnStatus::Disconnecting => "正在断开…",
        VpnStatus::Error => "连接错误…",
    }
}

/** 判断状态是否属于禁止重复操作的过渡阶段。 */
fn is_transition_status(status: VpnStatus) -> bool {
    matches!(status, VpnStatus::Connecting | VpnStatus::Disconnecting)
}

/** 判断状态是否代表已有或正在建立的 VPN 会话。 */
fn is_active_status(status: VpnStatus) -> bool {
    matches!(
        status,
        VpnStatus::Connecting
            | VpnStatus::Authenticating
            | VpnStatus::Connected
            | VpnStatus::Disconnecting
    )
}

/** 计算两条 VPN 的聚合托盘视觉状态。 */
fn resolve_visual_state(snapshot: &TraySnapshot) -> TrayVisualState {
    let statuses = [snapshot.fortinet.status, snapshot.atrust.status];
    if statuses
        .into_iter()
        .any(|status| matches!(status, VpnStatus::Authenticating | VpnStatus::Error))
    {
        return TrayVisualState::Attention;
    }
    let connected_count = statuses
        .into_iter()
        .filter(|status| *status == VpnStatus::Connected)
        .count();
    if connected_count == 2 {
        TrayVisualState::Connected
    } else if connected_count == 1 || statuses.into_iter().any(is_transition_status) {
        TrayVisualState::Partial
    } else {
        TrayVisualState::Disconnected
    }
}

/** 解码指定聚合状态对应的 PNG 托盘图标。 */
fn load_tray_icon(state: TrayVisualState) -> Result<Image<'static>, String> {
    let bytes = match state {
        TrayVisualState::Disconnected => ICON_DISCONNECTED,
        TrayVisualState::Partial => ICON_PARTIAL,
        TrayVisualState::Connected => ICON_CONNECTED,
        TrayVisualState::Attention => ICON_ATTENTION,
    };
    Image::from_bytes(bytes).map_err(|error| format!("加载托盘图标失败：{error}"))
}

/** 构建 Windows 与 macOS 共用的托盘悬停摘要。 */
fn build_tooltip(snapshot: &TraySnapshot) -> String {
    format!(
        "雨燕 SwiftVPN\n北京：{}\n长沙：{}",
        tooltip_vpn_line(&snapshot.fortinet),
        tooltip_vpn_line(&snapshot.atrust),
    )
}

/** 构建单条 VPN 的 Tooltip 状态行。 */
fn tooltip_vpn_line(snapshot: &TrayVpnSnapshot) -> String {
    if snapshot.status != VpnStatus::Connected {
        return status_label(snapshot.status)
            .trim_end_matches('…')
            .to_string();
    }
    let ip = snapshot.virtual_ip.as_deref().unwrap_or("IP 获取中");
    format!("已连接 · {ip} · {}", format_duration(snapshot.uptime))
}

/** 将秒数格式化为适合托盘展示的时长。 */
fn format_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let seconds = seconds % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

/** 发送前端路由导航事件。 */
fn emit_navigation(app_handle: &AppHandle, path: &str) {
    let _ = app_handle.emit(
        "tray-navigate",
        TrayNavigationPayload {
            path: path.to_string(),
        },
    );
}

/** 唤起主窗口并要求前端继续完成权限或登录配置。 */
fn require_frontend_action(
    app_handle: &AppHandle,
    action: TrayVpnAction,
    reason: &str,
    message: impl Into<String>,
    path: &str,
) {
    show_main_window(app_handle);
    let _ = app_handle.emit(
        "tray-action-required",
        TrayActionRequiredPayload {
            action: action.as_str().to_string(),
            reason: reason.to_string(),
            message: message.into(),
            path: path.to_string(),
        },
    );
}

/** 唤起主窗口并展示托盘异步操作错误。 */
fn report_operation_error(app_handle: &AppHandle, message: impl Into<String>) {
    show_main_window(app_handle);
    emit_navigation(app_handle, "/dashboard");
    let _ = app_handle.emit(
        "tray-operation-feedback",
        TrayFeedbackPayload {
            level: "error".to_string(),
            message: message.into(),
        },
    );
}

/** 启动单条 VPN 切换任务。 */
fn spawn_toggle(app_handle: &AppHandle, vpn_type: VpnType) {
    let app_handle = app_handle.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(error) = toggle_vpn(&app_handle, vpn_type).await {
            report_operation_error(&app_handle, error);
        }
    });
}

/** 启动全部 VPN 连接任务。 */
fn spawn_connect_all(app_handle: &AppHandle) {
    let app_handle = app_handle.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(error) = connect_all(&app_handle).await {
            report_operation_error(&app_handle, error);
        }
    });
}

/** 启动全部 VPN 断开任务。 */
fn spawn_disconnect_all(app_handle: &AppHandle) {
    let app_handle = app_handle.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(error) = disconnect_all(&app_handle).await {
            report_operation_error(&app_handle, error);
        }
    });
}

/** 按当前状态连接、断开或继续验证指定 VPN。 */
async fn toggle_vpn(app_handle: &AppHandle, vpn_type: VpnType) -> Result<(), String> {
    let manager = app_handle.state::<VpnManager>().inner().clone();
    let status = {
        let inner = manager.inner.lock().await;
        match vpn_type {
            VpnType::Fortinet => inner.fortinet_status,
            VpnType::Atrust => inner.atrust_status,
        }
    };
    match status {
        VpnStatus::Connected => disconnect_one(app_handle, &manager, vpn_type).await,
        VpnStatus::Authenticating => {
            show_main_window(app_handle);
            emit_navigation(app_handle, "/dashboard");
            Ok(())
        }
        VpnStatus::Connecting | VpnStatus::Disconnecting => Ok(()),
        VpnStatus::Disconnected | VpnStatus::Error => {
            let action = match vpn_type {
                VpnType::Fortinet => TrayVpnAction::Fortinet,
                VpnType::Atrust => TrayVpnAction::Atrust,
            };
            connect_one(app_handle, &manager, vpn_type, action).await
        }
    }
}

/** 从本地保存的登录配置启动指定 VPN。 */
async fn connect_one(
    app_handle: &AppHandle,
    manager: &VpnManager,
    vpn_type: VpnType,
    action: TrayVpnAction,
) -> Result<(), String> {
    let settings = vpn::load_vpn_config(app_handle.clone()).await?;
    let password = match vpn_type {
        VpnType::Fortinet => settings.fortinet.password,
        VpnType::Atrust => settings.atrust.password,
    }
    .filter(|password| !password.is_empty());
    let Some(password) = password else {
        require_frontend_action(
            app_handle,
            action,
            "missingPassword",
            "请先在登录信息中保存对应 VPN 密码，再使用托盘快速连接",
            "/settings",
        );
        return Ok(());
    };
    if !ensure_authorization(app_handle, manager, action).await? {
        return Ok(());
    }
    connect_with_password(app_handle, vpn_type, password).await
}

/** 使用已经验证的前置条件调用现有 Tauri VPN 命令。 */
async fn connect_with_password(
    app_handle: &AppHandle,
    vpn_type: VpnType,
    password: String,
) -> Result<(), String> {
    match vpn_type {
        VpnType::Fortinet => {
            vpn::fortinet::connect_fortinet(
                app_handle.clone(),
                app_handle.state::<VpnManager>(),
                password,
            )
            .await
        }
        VpnType::Atrust => {
            vpn::atrust::connect_atrust(
                app_handle.clone(),
                app_handle.state::<VpnManager>(),
                password,
            )
            .await
        }
    }
}

/** 连接当前尚未激活的全部 VPN。 */
async fn connect_all(app_handle: &AppHandle) -> Result<(), String> {
    let manager = app_handle.state::<VpnManager>().inner().clone();
    let snapshot = read_snapshot(&manager).await;
    let need_fortinet = !is_active_status(snapshot.fortinet.status);
    let need_atrust = !is_active_status(snapshot.atrust.status);
    if !need_fortinet && !need_atrust {
        return Ok(());
    }

    let settings = vpn::load_vpn_config(app_handle.clone()).await?;
    let fortinet_password = settings
        .fortinet
        .password
        .filter(|password| !password.is_empty());
    let atrust_password = settings
        .atrust
        .password
        .filter(|password| !password.is_empty());
    if (need_fortinet && fortinet_password.is_none()) || (need_atrust && atrust_password.is_none())
    {
        require_frontend_action(
            app_handle,
            TrayVpnAction::Both,
            "missingPassword",
            "请先补全并保存两条 VPN 的登录密码，再使用托盘连接全部 VPN",
            "/settings",
        );
        return Ok(());
    }
    if !ensure_authorization(app_handle, &manager, TrayVpnAction::Both).await? {
        return Ok(());
    }

    if need_fortinet {
        connect_with_password(
            app_handle,
            VpnType::Fortinet,
            fortinet_password.unwrap_or_default(),
        )
        .await?;
    }
    if need_fortinet && need_atrust {
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    }
    if need_atrust {
        connect_with_password(
            app_handle,
            VpnType::Atrust,
            atrust_password.unwrap_or_default(),
        )
        .await?;
    }
    Ok(())
}

/** 断开指定 VPN，并在需要时引导用户重新授权。 */
async fn disconnect_one(
    app_handle: &AppHandle,
    manager: &VpnManager,
    vpn_type: VpnType,
) -> Result<(), String> {
    let action = match vpn_type {
        VpnType::Fortinet => TrayVpnAction::Fortinet,
        VpnType::Atrust => TrayVpnAction::Atrust,
    };
    if !ensure_authorization(app_handle, manager, action).await? {
        return Ok(());
    }
    match vpn_type {
        VpnType::Fortinet => vpn::fortinet::disconnect_fortinet_managed(app_handle, manager).await,
        VpnType::Atrust => vpn::atrust::disconnect_atrust_managed(app_handle, manager).await,
    }
}

/** 并行断开全部活跃 VPN。 */
async fn disconnect_all(app_handle: &AppHandle) -> Result<(), String> {
    let manager = app_handle.state::<VpnManager>().inner().clone();
    let snapshot = read_snapshot(&manager).await;
    if !is_active_status(snapshot.fortinet.status) && !is_active_status(snapshot.atrust.status) {
        return Ok(());
    }
    if !ensure_authorization(app_handle, &manager, TrayVpnAction::DisconnectAll).await? {
        return Ok(());
    }
    let (fortinet_result, atrust_result) = tokio::join!(
        vpn::fortinet::disconnect_fortinet_managed(app_handle, &manager),
        vpn::atrust::disconnect_atrust_managed(app_handle, &manager),
    );
    let mut errors = Vec::new();
    if let Err(error) = fortinet_result {
        errors.push(format!("北京 VPN 断开失败：{error}"));
    }
    if let Err(error) = atrust_result {
        errors.push(format!("长沙 VPN 断开失败：{error}"));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("；"))
    }
}

/** 确保托盘操作具备当前平台所需的管理员权限。 */
async fn ensure_authorization(
    app_handle: &AppHandle,
    manager: &VpnManager,
    action: TrayVpnAction,
) -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        vpn::windows::ensure_helper(manager).await?;
        Ok(true)
    }
    #[cfg(target_os = "macos")]
    {
        if manager.inner.lock().await.sudo_password.is_some() {
            return Ok(true);
        }
        require_frontend_action(
            app_handle,
            action,
            "authorization",
            "需要先完成 macOS 系统权限验证，验证成功后会继续本次托盘操作",
            "/dashboard",
        );
        Ok(false)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = (app_handle, manager, action);
        Err("当前系统暂不支持托盘 VPN 操作".to_string())
    }
}

/** 切换开机后台启动状态。 */
fn toggle_autostart(app_handle: &AppHandle) {
    let autolaunch = app_handle.autolaunch();
    let enabled = autolaunch.is_enabled().unwrap_or(false);
    let result = if enabled {
        autolaunch.disable()
    } else {
        autolaunch.enable()
    };
    match result {
        Ok(()) => {
            if let Some(controller) = app_handle.try_state::<TrayController>() {
                let _ = controller.autostart.set_checked(!enabled);
            }
        }
        Err(error) => report_operation_error(app_handle, format!("切换开机启动失败：{error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        format_duration, resolve_visual_state, TraySnapshot, TrayVisualState, TrayVpnSnapshot,
    };
    use crate::vpn::VpnStatus;

    /** 创建托盘聚合状态测试快照。 */
    fn snapshot(fortinet: VpnStatus, atrust: VpnStatus) -> TraySnapshot {
        TraySnapshot {
            fortinet: TrayVpnSnapshot {
                status: fortinet,
                virtual_ip: None,
                uptime: 0,
            },
            atrust: TrayVpnSnapshot {
                status: atrust,
                virtual_ip: None,
                uptime: 0,
            },
        }
    }

    #[test]
    fn resolves_aggregate_visual_states() {
        assert_eq!(
            resolve_visual_state(&snapshot(VpnStatus::Disconnected, VpnStatus::Disconnected)),
            TrayVisualState::Disconnected
        );
        assert_eq!(
            resolve_visual_state(&snapshot(VpnStatus::Connected, VpnStatus::Disconnected)),
            TrayVisualState::Partial
        );
        assert_eq!(
            resolve_visual_state(&snapshot(VpnStatus::Connected, VpnStatus::Connected)),
            TrayVisualState::Connected
        );
        assert_eq!(
            resolve_visual_state(&snapshot(VpnStatus::Connected, VpnStatus::Authenticating)),
            TrayVisualState::Attention
        );
    }

    #[test]
    fn formats_uptime_for_tooltip() {
        assert_eq!(format_duration(0), "00:00:00");
        assert_eq!(format_duration(3_661), "01:01:01");
    }
}
