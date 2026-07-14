use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::Mutex;

pub mod atrust;
pub mod fortinet;
mod network_guard;
pub mod shutdown;

/** 空闲期间持续恢复异常退出或 Clash 重载后遗留的 Mihomo 静态出口。 */
pub async fn maintain_idle_network_state(manager: VpnManager) {
    loop {
        let status = manager.inner.lock().await.fortinet_status;
        if matches!(status, VpnStatus::Disconnected | VpnStatus::Error) {
            network_guard::recover_stale_mihomo_interface().await;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

/** 北京 Fortinet VPN 固定网关。 */
pub const FORTINET_HOST: &str = "fortinet.example.com";
/** 北京 Fortinet VPN 固定端口。 */
pub const FORTINET_PORT: u16 = 443;
/** 北京 Fortinet VPN 固定账号。 */
pub const FORTINET_USERNAME: &str = "sslvpn";
/** 北京 Fortinet VPN 固定内网路由。 */
pub const FORTINET_ROUTES: &[&str] = &["192.168.1.0/24"];
/** 长沙 aTrust VPN 固定网关。 */
pub const ATRUST_HOST: &str = "atrust.example.com";
/** 长沙 aTrust VPN 固定端口。 */
pub const ATRUST_PORT: u16 = 443;
/** 长沙 aTrust VPN 固定账号。 */
pub const ATRUST_USERNAME: &str = "atrustvpn";

/**
 * 解析当前构建模式下的 macOS sidecar 路径。
 *
 * Tauri 会把 externalBin 与主程序放在同一目录：开发模式为 `target/debug`，
 * 发布包为 `Contents/MacOS`。使用当前进程路径可避免路径解析器在 dev 下返回 unknown path。
 */
#[cfg(target_os = "macos")]
pub fn resolve_macos_sidecar(binary_name: &str) -> Result<std::path::PathBuf, String> {
    std::env::current_exe()
        .map_err(|error| format!("获取当前程序路径失败: {error}"))?
        .parent()
        .ok_or_else(|| "当前程序路径缺少父目录".to_string())
        .map(|directory| directory.join(binary_name))
}

/** 为非 macOS 构建提供类型检查兜底，运行时不会尝试启动 macOS Sidecar。 */
#[cfg(not(target_os = "macos"))]
pub fn resolve_macos_sidecar(_binary_name: &str) -> Result<std::path::PathBuf, String> {
    Err("当前操作系统不支持 macOS VPN Sidecar".to_string())
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum VpnType {
    Fortinet,
    Atrust,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum VpnStatus {
    Disconnected,
    Connecting,
    Authenticating, // 等待二次验证码
    Connected,
    Disconnecting,
    Error,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VpnConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub save_password: bool,
    pub custom_routes: Vec<String>, // 用户自定义的分流网段，如 "192.168.100.0/24"
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnStatePayload {
    pub vpn_type: VpnType,
    pub status: VpnStatus,
    pub message: String,
    pub virtual_ip: Option<String>,
    pub uptime: u64, // 连接时长（秒）
}

#[derive(Clone, Serialize)]
pub struct LogPayload {
    pub vpn_type: VpnType,
    pub text: String,
}

/**
 * 统一输出 VPN 原生日志。
 *
 * 日志会发送给前端、写入开发终端，并把关键诊断行追加到系统临时目录，
 * 便于进程提前退出或 UI 刷新后继续排查。
 */
pub fn emit_vpn_log(app_handle: &AppHandle, vpn_type: VpnType, text: impl Into<String>) {
    let text = text.into();
    let lower_text = text.to_lowercase();
    let trimmed_text = text.trim_start();
    let is_hex_dump = trimmed_text.len() > 9
        && trimmed_text.as_bytes()[..8]
            .iter()
            .all(|value| value.is_ascii_hexdigit())
        && trimmed_text.as_bytes()[8] == b' ';
    let is_sensitive = ["cookie:", "loaded password"]
        .iter()
        .any(|keyword| lower_text.contains(keyword))
        || (vpn_type == VpnType::Atrust
            && [
                "given auth data",
                "received client resource",
                "sid:",
                "signkey:",
            ]
            .iter()
            .any(|keyword| lower_text.contains(keyword)));
    let is_noisy_packet_dump = vpn_type == VpnType::Atrust
        && (is_hex_dump || lower_text.contains("send: wrote") || lower_text.contains("recv: read"));
    let is_noisy_fortinet_transport = vpn_type == VpnType::Fortinet
        && (lower_text.contains("pppd ---> gateway")
            || lower_text.contains("gateway ---> pppd")
            || lower_text.contains("if_config: not ready yet"));
    if is_sensitive || is_noisy_packet_dump || is_noisy_fortinet_transport {
        return;
    }

    let vpn_label = match vpn_type {
        VpnType::Fortinet => "Fortinet",
        VpnType::Atrust => "aTrust",
    };
    eprintln!("[VPN][{vpn_label}] {text}");

    let _ = app_handle.emit(
        "vpn-log",
        LogPayload {
            vpn_type,
            text: text.clone(),
        },
    );

    let is_diagnostic = (vpn_type == VpnType::Fortinet
        && [
            "error",
            "warn",
            "authenticated",
            "negotiation complete",
            "interface",
            "tunnel is up",
            "terminated",
        ]
        .iter()
        .any(|keyword| lower_text.contains(keyword)))
        || [
            "error",
            "failed",
            "no vpn resources",
            "add cidr",
            "add route",
            "interface name",
            "received ip",
            "use dns server",
            "aTrust TCP tunnel",
            "quick socks5",
            "shutdown",
            "whitelist",
        ]
        .iter()
        .any(|keyword| lower_text.contains(keyword));

    if is_diagnostic {
        use std::io::Write;
        let log_path = std::env::temp_dir().join("yuyan-vpn-diagnostic.log");
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
        {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let _ = writeln!(file, "[{timestamp}][{vpn_label}] {text}");
        }
    }
}

// 两个 VPN 独立的状态管理
pub struct VpnManagerInner {
    // 内存临时保存的 sudo 密码
    pub sudo_password: Option<String>,

    // Fortinet 状态与进程句柄
    pub fortinet_status: VpnStatus,
    pub fortinet_child: Option<tokio::process::Child>,
    pub fortinet_watcher: Option<tokio::task::JoinHandle<()>>,
    pub fortinet_network_watcher: Option<tokio::task::JoinHandle<()>>,
    pub fortinet_ip: Option<String>,
    pub fortinet_start_time: Option<std::time::Instant>,
    pub fortinet_gateway_host: Option<String>,
    pub fortinet_mihomo_state: Option<network_guard::MihomoRouteState>,
    pub fortinet_config_path: Option<std::path::PathBuf>,

    // aTrust 状态与进程句柄
    pub atrust_status: VpnStatus,
    pub atrust_child: Option<tokio::process::Child>,
    pub atrust_watcher: Option<tokio::task::JoinHandle<()>>,
    pub atrust_ip: Option<String>,
    pub atrust_start_time: Option<std::time::Instant>,
    pub atrust_stdin: Option<tokio::process::ChildStdin>,
    pub atrust_interface: Option<String>,
    pub atrust_route_ready: bool,
    pub atrust_stack_ready: bool,
    pub atrust_fifo_path: Option<std::path::PathBuf>,
    pub atrust_readiness_watcher: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Clone)]
pub struct VpnManager {
    pub inner: Arc<Mutex<VpnManagerInner>>,
    shutting_down: Arc<AtomicBool>,
}

impl VpnManager {
    /** 创建两个 VPN 共用的运行状态与安全退出门禁。 */
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(VpnManagerInner {
                sudo_password: None,
                fortinet_status: VpnStatus::Disconnected,
                fortinet_child: None,
                fortinet_watcher: None,
                fortinet_network_watcher: None,
                fortinet_ip: None,
                fortinet_start_time: None,
                fortinet_gateway_host: None,
                fortinet_mihomo_state: None,
                fortinet_config_path: None,
                atrust_status: VpnStatus::Disconnected,
                atrust_child: None,
                atrust_watcher: None,
                atrust_ip: None,
                atrust_start_time: None,
                atrust_stdin: None,
                atrust_interface: None,
                atrust_route_ready: false,
                atrust_stack_ready: false,
                atrust_fifo_path: None,
                atrust_readiness_watcher: None,
            })),
            shutting_down: Arc::new(AtomicBool::new(false)),
        }
    }

    /** 标记应用进入安全退出阶段，并阻止新连接继续创建特权子进程。 */
    pub fn begin_shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
    }

    /** 清理失败时重新开放连接能力，让用户可在应用内重试断开。 */
    pub fn cancel_shutdown(&self) {
        self.shutting_down.store(false, Ordering::SeqCst);
    }

    /** 判断应用是否已经进入安全退出阶段。 */
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    /** 在启动 sidecar 前执行统一门禁检查。 */
    pub fn ensure_connections_allowed(&self) -> Result<(), String> {
        if self.is_shutting_down() {
            Err("应用正在安全退出，已取消新的 VPN 连接".to_string())
        } else {
            Ok(())
        }
    }
}

// 统一保存配置和密码的方法（第一期先通过普通 JSON 读写，稍后扩展 Keychain）
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppVpnSettings {
    pub fortinet: VpnConfig,
    pub atrust: VpnConfig,
}

fn get_config_path(app_handle: &AppHandle) -> std::path::PathBuf {
    app_handle
        .path()
        .app_config_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join("vpn_config.json")
}

/**
 * 校验并规范化单条 IPv4 CIDR。
 *
 * 带主机位的输入会归一到对应网络地址，`/0` 会被拒绝以避免接管默认路由。
 */
fn normalize_ipv4_cidr(route: &str) -> Result<String, String> {
    let (address_text, prefix_text) = route
        .trim()
        .split_once('/')
        .ok_or_else(|| format!("无效的北京内网路由 {route}，请使用 IPv4 CIDR 格式"))?;
    let address = address_text
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| format!("无效的北京内网路由地址: {route}"))?;
    let prefix = prefix_text
        .parse::<u8>()
        .map_err(|_| format!("无效的北京内网路由掩码: {route}"))?;
    if !(1..=32).contains(&prefix) {
        return Err(format!("北京内网路由掩码必须在 1 到 32 之间: {route}"));
    }

    let mask = if prefix == 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = std::net::Ipv4Addr::from(u32::from(address) & mask);
    Ok(format!("{network}/{prefix}"))
}

/** 合并内置路由与用户附加路由，并保持顺序去重。 */
fn normalize_fortinet_routes(routes: &[String]) -> Result<Vec<String>, String> {
    let mut normalized_routes = Vec::new();
    for route in FORTINET_ROUTES
        .iter()
        .copied()
        .map(str::to_string)
        .chain(routes.iter().cloned())
    {
        let normalized_route = normalize_ipv4_cidr(&route)?;
        if !normalized_routes.contains(&normalized_route) {
            normalized_routes.push(normalized_route);
        }
    }
    Ok(normalized_routes)
}

/** 将可持久化设置规范为安装包内置的服务器参数，并保留有效的附加路由。 */
fn normalize_settings(mut settings: AppVpnSettings) -> Result<AppVpnSettings, String> {
    settings.fortinet.enabled = true;
    settings.fortinet.custom_routes = normalize_fortinet_routes(&settings.fortinet.custom_routes)?;

    settings.atrust.enabled = true;
    settings.atrust.custom_routes.clear();
    Ok(settings)
}

/** 返回无需用户配置网络参数的内置 VPN 设置。 */
fn default_settings() -> AppVpnSettings {
    AppVpnSettings {
        fortinet: VpnConfig {
            enabled: true,
            host: FORTINET_HOST.to_string(),
            port: FORTINET_PORT,
            username: FORTINET_USERNAME.to_string(),
            password: None,
            save_password: false,
            custom_routes: FORTINET_ROUTES
                .iter()
                .map(|route| (*route).to_string())
                .collect(),
        },
        atrust: VpnConfig {
            enabled: true,
            host: ATRUST_HOST.to_string(),
            port: ATRUST_PORT,
            username: ATRUST_USERNAME.to_string(),
            password: None,
            save_password: false,
            custom_routes: Vec::new(),
        },
    }
}

#[tauri::command]
pub async fn save_vpn_config(
    app_handle: AppHandle,
    settings: AppVpnSettings,
) -> Result<(), String> {
    let path = get_config_path(&app_handle);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let normalized_settings = normalize_settings(settings)?;
    let json_str = serde_json::to_string_pretty(&normalized_settings)
        .map_err(|e| format!("序列化配置失败: {e}"))?;
    std::fs::write(&path, json_str).map_err(|e| format!("写入配置文件失败: {e}"))?;
    Ok(())
}

#[tauri::command]
pub async fn load_vpn_config(app_handle: AppHandle) -> Result<AppVpnSettings, String> {
    let path = get_config_path(&app_handle);
    if !path.exists() {
        return Ok(default_settings());
    }
    let json_str = std::fs::read_to_string(&path).map_err(|e| format!("读取配置文件失败: {e}"))?;
    let settings: AppVpnSettings =
        serde_json::from_str(&json_str).map_err(|e| format!("解析配置文件失败: {e}"))?;
    normalize_settings(settings)
}

#[tauri::command]
pub async fn verify_sudo_password(
    state: State<'_, VpnManager>,
    password: String,
) -> Result<bool, String> {
    // 通过跑一个简单的 sudo -S id 命令来验证密码是否正确
    let mut child = tokio::process::Command::new("sudo")
        .arg("-S")
        .arg("id")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("无法启动提权验证进程: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        let _ = stdin.write_all(format!("{password}\n").as_bytes()).await;
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("提权进程执行错误: {e}"))?;

    if output.status.success() {
        let mut inner = state.inner.lock().await;
        inner.sudo_password = Some(password);
        Ok(true)
    } else {
        Ok(false)
    }
}

/// 返回当前 App 会话是否已经保存过经验证的 sudo 密码。
#[tauri::command]
pub async fn has_sudo_credentials(state: State<'_, VpnManager>) -> Result<bool, String> {
    Ok(state.inner.lock().await.sudo_password.is_some())
}

#[tauri::command]
pub async fn get_vpn_state(
    state: State<'_, VpnManager>,
    vpn_type: VpnType,
) -> Result<VpnStatePayload, String> {
    let inner = state.inner.lock().await;
    let (status, ip, start_time) = match vpn_type {
        VpnType::Fortinet => (
            inner.fortinet_status,
            &inner.fortinet_ip,
            inner.fortinet_start_time,
        ),
        VpnType::Atrust => (
            inner.atrust_status,
            &inner.atrust_ip,
            inner.atrust_start_time,
        ),
    };

    let uptime = start_time.map(|t| t.elapsed().as_secs()).unwrap_or(0);

    Ok(VpnStatePayload {
        vpn_type,
        status,
        message: match status {
            VpnStatus::Disconnected => "未连接".to_string(),
            VpnStatus::Connecting => "正在建立安全通道...".to_string(),
            VpnStatus::Authenticating => "等待二次验证...".to_string(),
            VpnStatus::Connected => "已连接，内网路由已就绪".to_string(),
            VpnStatus::Disconnecting => "正在断开...".to_string(),
            VpnStatus::Error => "连接出错，请检查日志".to_string(),
        },
        virtual_ip: ip.clone(),
        uptime,
    })
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnAuthPayload {
    pub vpn_type: VpnType,
    pub prompt: String,
}

#[tauri::command]
pub async fn submit_vpn_mfa(state: State<'_, VpnManager>, code: String) -> Result<(), String> {
    use tokio::io::AsyncWriteExt;
    let mut inner = state.inner.lock().await;
    if let Some(mut stdin) = inner.atrust_stdin.take() {
        stdin
            .write_all(format!("{code}\n").as_bytes())
            .await
            .map_err(|e| format!("写入二次验证码失败: {e}"))?;
        // 写完后将其保留，以防万一后续还需要 stdin
        inner.atrust_stdin = Some(stdin);
        Ok(())
    } else {
        Err("当前未处于等待二次认证验证码的状态".to_string())
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnCaptchaPayload {
    pub vpn_type: VpnType,
    pub url: String,
}

#[cfg(test)]
mod tests {
    use super::{normalize_fortinet_routes, normalize_ipv4_cidr};

    /** 验证带主机位的输入会归一为网络地址。 */
    #[test]
    fn normalizes_ipv4_cidr_network_address() {
        assert_eq!(
            normalize_ipv4_cidr("192.168.111.64/24"),
            Ok("192.168.111.0/24".to_string())
        );
        assert_eq!(
            normalize_ipv4_cidr("192.168.111.64/32"),
            Ok("192.168.111.64/32".to_string())
        );
    }

    /** 验证默认路由始终存在，附加路由会规范化并去重。 */
    #[test]
    fn merges_built_in_and_additional_fortinet_routes() {
        let routes = vec![
            "192.168.111.64/24".to_string(),
            "192.168.100.0/24".to_string(),
        ];

        assert_eq!(
            normalize_fortinet_routes(&routes),
            Ok(vec![
                "192.168.100.0/24".to_string(),
                "192.168.111.64/32".to_string(),
                "192.168.111.0/24".to_string(),
            ])
        );
    }

    /** 验证默认路由和缺少掩码的输入会被拒绝。 */
    #[test]
    fn rejects_unsafe_or_invalid_fortinet_routes() {
        assert!(normalize_ipv4_cidr("0.0.0.0/0").is_err());
        assert!(normalize_ipv4_cidr("192.168.111.0").is_err());
    }
}
