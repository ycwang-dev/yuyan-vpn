use super::network_guard::{
    follow_mihomo_interface, pin_mihomo_interface, restore_mihomo_interface,
};
use super::{
    emit_vpn_log, load_vpn_config, resolve_macos_sidecar, validate_vpn_connection_config,
    VpnManager, VpnManagerInner, VpnStatePayload, VpnStatus, VpnType,
};
use std::collections::HashSet;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Output, Stdio};
use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

/** 创建仅限当前用户读取的 Fortinet 临时配置文件。 */
fn write_secure_config(path: &std::path::Path, content: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options.open(path)?;
    std::io::Write::write_all(&mut file, content)
}

/** macOS 连接 VPN 前的主网络出口。 */
#[derive(Clone, PartialEq, Eq)]
struct PrimaryNetworkState {
    interface: String,
    service: String,
    router: String,
}

/** 公网网关路由的处理结果。 */
#[derive(Debug, PartialEq, Eq)]
enum GatewayRouteOutcome {
    /** 现有路由已经使用正确物理出口，无需由 App 管理。 */
    Unchanged,
    /** 目标是 Mihomo Fake-IP，必须保留 TUN 接管完成域名映射。 */
    ProxyManaged,
    /** App 新增了主机路由，断开时只删除该数值地址。 */
    Added(String),
}

/** 判断接口是否可作为公网物理出口，排除 PPP 与各类 TUN 虚拟接口。 */
fn is_physical_interface(interface_name: &str) -> bool {
    interface_name.starts_with("en") || interface_name.starts_with("bridge")
}

/** 将 Fortinet 启动阶段恢复为可重试的错误状态。 */
async fn mark_start_error(manager: &VpnManager) {
    let mut inner = manager.inner.lock().await;
    inner.fortinet_status = VpnStatus::Error;
    inner.fortinet_start_time = None;
    inner.fortinet_ip = None;
    inner.fortinet_gateway_host = None;
}

/** 在修改 Mihomo 出口前验证 Fortinet 网关可建立 TCP，避免无效配置拖垮公网。 */
async fn verify_gateway_reachable(host: &str, port: u16) -> Result<(), String> {
    match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect((host, port)),
    )
    .await
    {
        Ok(Ok(stream)) => {
            drop(stream);
            Ok(())
        }
        Ok(Err(error)) => Err(format!("北京 VPN 网关连接预检失败: {error}")),
        Err(_) => Err("北京 VPN 网关连接预检超时，请检查当前公网、代理或服务器配置".to_string()),
    }
}

/** 读取 macOS 当前主网络接口与默认网关。 */
async fn get_primary_network_state() -> Result<PrimaryNetworkState, String> {
    let mut child = tokio::process::Command::new("scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| format!("无法启动 scutil: {error}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(b"show State:/Network/Global/IPv4\nquit\n")
            .await
            .map_err(|error| format!("无法查询系统主网络: {error}"))?;
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|error| format!("查询系统主网络失败: {error}"))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut interface = None;
    let mut service = None;
    let mut router = None;

    for line in text.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("PrimaryInterface :") {
            interface = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("PrimaryService :") {
            service = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("Router :") {
            router = Some(value.trim().to_string());
        }
    }

    match (interface, service, router) {
        (Some(interface), Some(service), Some(router))
            if !interface.is_empty() && !service.is_empty() && !router.is_empty() =>
        {
            Ok(PrimaryNetworkState {
                interface,
                service,
                router,
            })
        }
        _ => Err("无法取得连接前的系统主网关状态，已停止连接".to_string()),
    }
}

/** 通过 sudo 执行单个系统命令并完整收集退出结果。 */
async fn run_sudo_command(
    sudo_password: &str,
    program: &str,
    args: &[&str],
) -> Result<Output, String> {
    let mut child = tokio::process::Command::new("sudo")
        .arg("-S")
        .arg("-p")
        .arg("")
        .arg(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("无法执行 {program}: {error}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(format!("{sudo_password}\n").as_bytes())
            .await
            .map_err(|error| format!("无法向 sudo 写入凭据: {error}"))?;
    }

    child
        .wait_with_output()
        .await
        .map_err(|error| format!("等待 {program} 执行失败: {error}"))
}

/** 优先按本次受管 sidecar 的独立进程组结束 sudo、VPN 引擎及其 PPP 子进程。 */
async fn terminate_managed_process_group(sudo_password: &str, process_id: u32) {
    let process_group = format!("-{process_id}");
    let _ = run_sudo_command(sudo_password, "kill", &["-TERM", &process_group]).await;
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    let _ = run_sudo_command(sudo_password, "kill", &["-KILL", &process_group]).await;
}

/** 使用 sudo 执行需要额外标准输入的系统命令。 */
async fn run_sudo_command_with_input(
    sudo_password: &str,
    program: &str,
    args: &[&str],
    input: &str,
) -> Result<Output, String> {
    let mut child = tokio::process::Command::new("sudo")
        .arg("-S")
        .arg("-p")
        .arg("")
        .arg(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("无法执行 {program}: {error}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(format!("{sudo_password}\n{input}").as_bytes())
            .await
            .map_err(|error| format!("无法向 {program} 写入输入: {error}"))?;
    }

    child
        .wait_with_output()
        .await
        .map_err(|error| format!("等待 {program} 执行失败: {error}"))
}

/** 返回当前存在的 PPP 接口集合，避免把其它 VPN 的接口误判为本次连接。 */
async fn list_ppp_interfaces() -> HashSet<String> {
    tokio::process::Command::new("ifconfig")
        .arg("-l")
        .output()
        .await
        .ok()
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .split_whitespace()
                .filter(|name| name.starts_with("ppp"))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/** 判断指定网络接口当前是否存在。 */
async fn interface_exists(interface_name: &str) -> bool {
    tokio::process::Command::new("ifconfig")
        .arg(interface_name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|status| status.success())
        .unwrap_or(false)
}

/** 读取 PPP 接口分配的 IPv4 地址。 */
async fn interface_ipv4(interface_name: &str) -> Option<String> {
    let output = tokio::process::Command::new("ifconfig")
        .arg(interface_name)
        .output()
        .await
        .ok()?;

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("inet ")
                .and_then(|value| value.split_whitespace().next())
                .map(str::to_string)
        })
}

/** 查找 configd 为指定 PPP 接口创建的临时网络服务 ID。 */
async fn find_ppp_network_service(interface_name: &str) -> Option<String> {
    let mut child = tokio::process::Command::new("scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(b"list State:/Network/Service/.*/IPv4\nquit\n")
            .await
            .ok()?;
    }
    let output = child.wait_with_output().await.ok()?;
    let services = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let marker = "State:/Network/Service/";
            let start = line.find(marker)? + marker.len();
            let remainder = &line[start..];
            let end = remainder.find("/IPv4")?;
            Some(remainder[..end].to_string())
        })
        .collect::<HashSet<_>>();

    for service in services {
        let mut query = tokio::process::Command::new("scutil")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        if let Some(mut stdin) = query.stdin.take() {
            stdin
                .write_all(format!("show State:/Network/Service/{service}/IPv4\nquit\n").as_bytes())
                .await
                .ok()?;
        }
        let state = query.wait_with_output().await.ok()?;
        if String::from_utf8_lossy(&state.stdout)
            .lines()
            .any(|line| line.trim() == format!("InterfaceName : {interface_name}"))
        {
            return Some(service);
        }
    }

    None
}

/** 判断系统当前选中的默认路由是否指向指定接口。 */
async fn default_route_uses_interface(interface_name: &str) -> bool {
    tokio::process::Command::new("route")
        .args(["-n", "get", "default"])
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

/**
 * 摘除 configd 注册的 PPP 主网络状态，只保留 PPP 接口供内网路由使用。
 */
async fn detach_ppp_network_service(
    sudo_password: &str,
    service: &str,
    primary_network: &PrimaryNetworkState,
) -> Result<(), String> {
    let script = format!(
        "remove State:/Network/Service/{service}/DNS\n\
         remove State:/Network/Service/{service}/IPv4\n\
         d.init\n\
         d.add PrimaryInterface {}\n\
         d.add PrimaryService {}\n\
         d.add Router {}\n\
         set State:/Network/Global/IPv4\n\
         quit\n",
        primary_network.interface, primary_network.service, primary_network.router
    );
    let output = run_sudo_command_with_input(sudo_password, "scutil", &[], &script).await?;
    if !output.status.success() {
        return Err(format!(
            "摘除 PPP 临时网络服务失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/** 删除 PPP 默认路由并恢复连接前主网络，避免公网和 DNS 被企业隧道接管。 */
async fn repair_primary_network(
    sudo_password: &str,
    interface_name: &str,
    primary_network: &PrimaryNetworkState,
) -> Result<(), String> {
    if default_route_uses_interface(interface_name).await {
        let output = run_sudo_command(
            sudo_password,
            "route",
            &[
                "-n",
                "delete",
                "-net",
                "default",
                "-interface",
                interface_name,
            ],
        )
        .await?;
        if !output.status.success() {
            return Err(format!(
                "删除 {interface_name} 默认路由失败: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
    }

    if let Some(service) = find_ppp_network_service(interface_name).await {
        detach_ppp_network_service(sudo_password, &service, primary_network).await?;
        let _ = run_sudo_command(sudo_password, "dscacheutil", &["-flushcache"]).await;
        let _ = run_sudo_command(sudo_password, "killall", &["-HUP", "mDNSResponder"]).await;
    }

    Ok(())
}

/** 将 CIDR 转为 route 查询所需的目标地址。 */
fn route_destination(route: &str) -> &str {
    route.split('/').next().unwrap_or(route)
}

/** 验证目标网段是否确实由指定接口承载。 */
async fn route_uses_interface(route: &str, interface_name: &str) -> bool {
    tokio::process::Command::new("route")
        .args(["-n", "get", route_destination(route)])
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

/** 为北京内网安装并验证 Fortinet 分流路由。 */
async fn install_split_routes(
    sudo_password: &str,
    routes: &[String],
    interface_name: &str,
) -> Result<(), String> {
    if routes.is_empty() {
        return Err("北京服务器 VPN 未配置任何内网路由".to_string());
    }

    for route in routes {
        if route_destination(route)
            .parse::<std::net::Ipv4Addr>()
            .is_err()
        {
            return Err(format!("无效的北京内网路由: {route}"));
        }

        let _ = run_sudo_command(sudo_password, "route", &["-n", "delete", "-net", route]).await;
        let output = run_sudo_command(
            sudo_password,
            "route",
            &["-n", "add", "-net", route, "-interface", interface_name],
        )
        .await?;

        if !output.status.success() {
            return Err(format!(
                "安装北京内网路由 {route} 失败: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        if !route_uses_interface(route, interface_name).await {
            return Err(format!("北京内网路由 {route} 未指向 {interface_name}"));
        }
    }

    Ok(())
}

/** 确保公网 VPN 网关始终从连接前的物理网络出口访问，避免被其它 TUN 捕获。 */
async fn ensure_gateway_route(
    sudo_password: &str,
    host: &str,
    primary_network: &PrimaryNetworkState,
) -> Result<GatewayRouteOutcome, String> {
    let current = tokio::process::Command::new("route")
        .args(["-n", "get", host])
        .output()
        .await
        .map_err(|error| format!("查询北京 VPN 网关路由失败: {error}"))?;
    if !current.status.success() {
        return Err(format!(
            "无法解析北京 VPN 网关或查询其路由: {}",
            String::from_utf8_lossy(&current.stderr).trim()
        ));
    }
    let current_text = String::from_utf8_lossy(&current.stdout);
    let destination = routed_ipv4_destination(&current_text)
        .or_else(|| host.parse::<std::net::Ipv4Addr>().ok())
        .ok_or("北京 VPN 网关没有可用的 IPv4 路由")?;

    if is_mihomo_fake_ip(destination) {
        if route_matches_primary_network(&current_text, primary_network) {
            let destination = destination.to_string();
            let removed = run_sudo_command(
                sudo_password,
                "route",
                &["-n", "delete", "-host", &destination],
            )
            .await?;
            if !removed.status.success() {
                return Err(format!(
                    "清理遗留 Fake-IP 主机路由失败: {}",
                    String::from_utf8_lossy(&removed.stderr).trim()
                ));
            }
        }
        return Ok(GatewayRouteOutcome::ProxyManaged);
    }

    if route_matches_primary_network(&current_text, primary_network) {
        return Ok(GatewayRouteOutcome::Unchanged);
    }

    let destination = destination.to_string();

    let _ = run_sudo_command(
        sudo_password,
        "route",
        &["-n", "delete", "-host", &destination],
    )
    .await;

    let output = run_sudo_command(
        sudo_password,
        "route",
        &["-n", "add", "-host", &destination, &primary_network.router],
    )
    .await?;
    if !output.status.success() {
        return Err(format!(
            "固定北京 VPN 网关出口失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let verified = tokio::process::Command::new("route")
        .args(["-n", "get", &destination])
        .output()
        .await
        .map_err(|error| format!("复核北京 VPN 网关路由失败: {error}"))?;
    if !verified.status.success()
        || !route_matches_primary_network(
            &String::from_utf8_lossy(&verified.stdout),
            primary_network,
        )
    {
        return Err("北京 VPN 网关主机路由未指向当前物理出口".to_string());
    }

    Ok(GatewayRouteOutcome::Added(destination))
}

/** 从 `route -n get` 输出提取实际 IPv4 目标。 */
fn routed_ipv4_destination(route_information: &str) -> Option<std::net::Ipv4Addr> {
    route_information.lines().find_map(|line| {
        line.trim()
            .strip_prefix("destination:")
            .and_then(|value| value.trim().parse().ok())
    })
}

/** 判断地址是否位于 Mihomo/Clash 常用的 `198.18.0.0/15` Fake-IP 网段。 */
fn is_mihomo_fake_ip(address: std::net::Ipv4Addr) -> bool {
    let octets = address.octets();
    octets[0] == 198 && matches!(octets[1], 18 | 19)
}

/** 判断公网网关主机路由是否同时匹配当前物理接口与网关。 */
fn route_matches_primary_network(
    route_information: &str,
    primary_network: &PrimaryNetworkState,
) -> bool {
    let expected_interface = format!("interface: {}", primary_network.interface);
    let expected_gateway = format!("gateway: {}", primary_network.router);
    let mut interface_matches = false;
    let mut gateway_matches = false;
    for line in route_information.lines().map(str::trim) {
        interface_matches |= line == expected_interface;
        gateway_matches |= line == expected_gateway;
    }
    interface_matches && gateway_matches
}

/** 清理本次连接主动添加的公网网关主机路由。 */
async fn remove_gateway_route(sudo_password: &str, host: &str) {
    let _ = run_sudo_command(sudo_password, "route", &["-n", "delete", "-host", host]).await;
}

/** 发送 Fortinet 状态事件。 */
fn emit_status(
    app_handle: &AppHandle,
    status: VpnStatus,
    message: impl Into<String>,
    virtual_ip: Option<String>,
) {
    let _ = app_handle.emit(
        "vpn-status-changed",
        VpnStatePayload {
            vpn_type: VpnType::Fortinet,
            status,
            message: message.into(),
            virtual_ip,
            uptime: 0,
        },
    );
}

/** 读取并转发 openfortivpn 的单路日志。 */
async fn forward_logs<R>(reader: R, app_handle: AppHandle)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(text)) = lines.next_line().await {
        emit_vpn_log(&app_handle, VpnType::Fortinet, text);
    }
}

/** 等待本次新建的 PPP 接口，安装路由后才把连接标记为可用。 */
async fn maintain_split_network(
    sudo_password: String,
    existing_ppp_interfaces: HashSet<String>,
    custom_routes: Vec<String>,
    mut primary_network: PrimaryNetworkState,
    gateway_host: String,
    manager: Arc<Mutex<VpnManagerInner>>,
    app_handle: AppHandle,
) {
    let readiness = tokio::time::timeout(std::time::Duration::from_secs(75), async {
        let interface_name = loop {
            let status = manager.lock().await.fortinet_status;
            if matches!(
                status,
                VpnStatus::Disconnected | VpnStatus::Disconnecting | VpnStatus::Error
            ) {
                return None;
            }

            let current = list_ppp_interfaces().await;
            if let Some(interface) = current.difference(&existing_ppp_interfaces).next().cloned() {
                break interface;
            }
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        };

        let assigned_ip = loop {
            let status = manager.lock().await.fortinet_status;
            if matches!(
                status,
                VpnStatus::Disconnected | VpnStatus::Disconnecting | VpnStatus::Error
            ) {
                return None;
            }

            if let Some(ip) = interface_ipv4(&interface_name)
                .await
                .filter(|ip| ip != "0.0.0.0")
            {
                break ip;
            }
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        };

        Some((interface_name, assigned_ip))
    })
    .await;

    let (interface_name, assigned_ip) = match readiness {
        Ok(Some(readiness)) => readiness,
        Ok(None) => return,
        Err(_) => {
            let (process_id, gateway_target, mihomo_state) = {
                let mut inner = manager.lock().await;
                if inner.fortinet_status != VpnStatus::Connecting {
                    return;
                }
                inner.fortinet_status = VpnStatus::Error;
                inner.fortinet_ip = None;
                inner.fortinet_start_time = None;
                (
                    inner.fortinet_child.as_ref().and_then(|child| child.id()),
                    inner.fortinet_gateway_host.take(),
                    inner.fortinet_mihomo_state.take(),
                )
            };

            let error = "北京服务器 VPN 在 75 秒内未建立 PPP 通道，已终止连接并恢复公网";
            emit_vpn_log(&app_handle, VpnType::Fortinet, error);
            emit_status(&app_handle, VpnStatus::Error, error, None);
            if let Some(process_id) = process_id {
                terminate_managed_process_group(&sudo_password, process_id).await;
            } else {
                let _ = run_sudo_command(&sudo_password, "killall", &["openfortivpn"]).await;
            }
            if let Some(gateway_target) = gateway_target {
                remove_gateway_route(&sudo_password, &gateway_target).await;
            }
            restore_mihomo_interface(mihomo_state).await;
            return;
        }
    };

    if let Err(error) =
        repair_primary_network(&sudo_password, &interface_name, &primary_network).await
    {
        {
            let mut inner = manager.lock().await;
            inner.fortinet_status = VpnStatus::Error;
            inner.fortinet_ip = None;
            inner.fortinet_start_time = None;
        }
        emit_vpn_log(&app_handle, VpnType::Fortinet, error.clone());
        emit_status(&app_handle, VpnStatus::Error, error, None);
        let _ = run_sudo_command(&sudo_password, "killall", &["openfortivpn"]).await;
        return;
    }

    if let Err(error) = install_split_routes(&sudo_password, &custom_routes, &interface_name).await
    {
        {
            let mut inner = manager.lock().await;
            inner.fortinet_status = VpnStatus::Error;
            inner.fortinet_ip = None;
            inner.fortinet_start_time = None;
        }
        emit_vpn_log(&app_handle, VpnType::Fortinet, error.clone());
        emit_status(&app_handle, VpnStatus::Error, error, None);
        let _ = run_sudo_command(&sudo_password, "killall", &["openfortivpn"]).await;
        return;
    }

    {
        let mut inner = manager.lock().await;
        inner.fortinet_ip = Some(assigned_ip.clone());
        inner.fortinet_status = VpnStatus::Connected;
    }
    emit_status(
        &app_handle,
        VpnStatus::Connected,
        "北京服务器 VPN 已连接，内网路由已就绪",
        Some(assigned_ip),
    );

    while interface_exists(&interface_name).await {
        let status = manager.lock().await.fortinet_status;
        if matches!(status, VpnStatus::Disconnected | VpnStatus::Disconnecting) {
            return;
        }
        if let Ok(current_network) = get_primary_network_state().await {
            if is_physical_interface(&current_network.interface)
                && current_network != primary_network
            {
                emit_vpn_log(
                    &app_handle,
                    VpnType::Fortinet,
                    format!(
                        "检测到公网出口切换：{} ({}) -> {} ({})",
                        primary_network.interface,
                        primary_network.router,
                        current_network.interface,
                        current_network.router
                    ),
                );
                primary_network = current_network;
                if let Err(error) = follow_mihomo_interface(&primary_network.interface).await {
                    emit_vpn_log(&app_handle, VpnType::Fortinet, error);
                }
            }
        }

        match ensure_gateway_route(&sudo_password, &gateway_host, &primary_network).await {
            Ok(GatewayRouteOutcome::Added(route_target)) => {
                manager.lock().await.fortinet_gateway_host = Some(route_target);
            }
            Ok(GatewayRouteOutcome::Unchanged | GatewayRouteOutcome::ProxyManaged) => {}
            Err(error) => emit_vpn_log(&app_handle, VpnType::Fortinet, error),
        }

        if let Err(error) =
            repair_primary_network(&sudo_password, &interface_name, &primary_network).await
        {
            emit_vpn_log(&app_handle, VpnType::Fortinet, error);
        }
        for route in &custom_routes {
            if !route_uses_interface(route, &interface_name).await {
                if let Err(error) =
                    install_split_routes(&sudo_password, &[route.clone()], &interface_name).await
                {
                    emit_vpn_log(&app_handle, VpnType::Fortinet, error);
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    let mut inner = manager.lock().await;
    if inner.fortinet_status == VpnStatus::Connected {
        inner.fortinet_status = VpnStatus::Error;
        inner.fortinet_ip = None;
        inner.fortinet_start_time = None;
        drop(inner);
        emit_status(
            &app_handle,
            VpnStatus::Error,
            "北京服务器 VPN 隧道已断开",
            None,
        );
    }
}

/** 连接北京 Fortinet VPN，并仅注入北京内网所需的分流路由。 */
#[tauri::command]
pub async fn connect_fortinet(
    app_handle: AppHandle,
    state: tauri::State<'_, VpnManager>,
    password: String,
) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        if password.contains('\r') || password.contains('\n') {
            return Err("北京服务器 VPN 密码不能包含换行符".to_string());
        }
        let fortinet_config = load_vpn_config(app_handle.clone()).await?.fortinet;
        validate_vpn_connection_config("Fortinet", &fortinet_config)?;
        return super::windows::connect_fortinet(
            &app_handle,
            state.inner(),
            fortinet_config,
            password,
        )
        .await;
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        return Err("当前操作系统暂不支持北京服务器 VPN 连接".to_string());
    }

    state.inner().ensure_connections_allowed()?;

    if password.contains('\r') || password.contains('\n') {
        return Err("北京服务器 VPN 密码不能包含换行符".to_string());
    }

    let openfortivpn_bin = resolve_macos_sidecar("openfortivpn")?;

    if !openfortivpn_bin.is_file() {
        return Err(format!(
            "安装包缺少当前架构的 openfortivpn: {}",
            openfortivpn_bin.display()
        ));
    }

    let fortinet_config = load_vpn_config(app_handle.clone()).await?.fortinet;
    validate_vpn_connection_config("Fortinet", &fortinet_config)?;
    let host = fortinet_config.host.clone();
    let port = fortinet_config.port;
    let username = fortinet_config.username.clone();
    let custom_routes = fortinet_config.custom_routes;

    let sudo_password = {
        let mut inner = state.inner.lock().await;
        if matches!(
            inner.fortinet_status,
            VpnStatus::Connecting | VpnStatus::Connected
        ) {
            return Err("北京服务器 VPN 已经连接或正在连接中".to_string());
        }
        let sudo_password = inner
            .sudo_password
            .clone()
            .ok_or("请先验证 macOS 系统权限")?;
        inner.fortinet_status = VpnStatus::Connecting;
        inner.fortinet_start_time = Some(std::time::Instant::now());
        inner.fortinet_ip = None;
        inner.fortinet_gateway_host = None;
        sudo_password
    };
    // 清理由旧版本或异常退出遗留的无限重连进程，避免与本次 PPP 会话争用。
    let _ = run_sudo_command(&sudo_password, "killall", &["openfortivpn"]).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    if let Err(error) = state.inner().ensure_connections_allowed() {
        mark_start_error(&state).await;
        return Err(error);
    }

    let primary_network = match get_primary_network_state().await {
        Ok(network) => network,
        Err(error) => {
            mark_start_error(&state).await;
            return Err(error);
        }
    };
    let existing_ppp_interfaces = list_ppp_interfaces().await;

    let gateway_route_target =
        match ensure_gateway_route(&sudo_password, &host, &primary_network).await {
            Ok(GatewayRouteOutcome::Added(route_target)) => Some(route_target),
            Ok(GatewayRouteOutcome::ProxyManaged) => {
                emit_vpn_log(
                    &app_handle,
                    VpnType::Fortinet,
                    "检测到 Mihomo Fake-IP，保留 TUN 接管 VPN 网关连接",
                );
                None
            }
            Ok(GatewayRouteOutcome::Unchanged) => None,
            Err(error) => {
                mark_start_error(&state).await;
                return Err(error);
            }
        };
    if let Some(route_target) = gateway_route_target.as_ref() {
        state.inner.lock().await.fortinet_gateway_host = Some(route_target.clone());
    }

    if let Err(error) = verify_gateway_reachable(&host, port).await {
        if let Some(route_target) = gateway_route_target.as_ref() {
            remove_gateway_route(&sudo_password, route_target).await;
        }
        state.inner.lock().await.fortinet_gateway_host = None;
        mark_start_error(&state).await;
        return Err(error);
    }

    let mihomo_state = match pin_mihomo_interface(&primary_network.interface).await {
        Ok(state) => state,
        Err(error) => {
            if let Some(route_target) = gateway_route_target.as_ref() {
                remove_gateway_route(&sudo_password, route_target).await;
            }
            state.inner.lock().await.fortinet_gateway_host = None;
            mark_start_error(&state).await;
            return Err(format!("固定公网代理出口失败: {error}"));
        }
    };
    state.inner.lock().await.fortinet_mihomo_state = mihomo_state;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let temp_config_path = std::env::temp_dir().join(format!("openfortivpn-{timestamp}.conf"));
    let config = format!(
        "host = {host}\nport = {port}\nusername = {username}\npassword = {password}\ntrusted-cert = 491a5bbe4cc44c3e42141d9babfbdd29eee75aaf36401221a1dac9305c846b56\ninsecure-ssl = 1\n"
    );
    if let Err(error) = write_secure_config(&temp_config_path, config.as_bytes()) {
        if let Some(route_target) = gateway_route_target.as_ref() {
            remove_gateway_route(&sudo_password, route_target).await;
        }
        state.inner.lock().await.fortinet_gateway_host = None;
        let mihomo_state = state.inner.lock().await.fortinet_mihomo_state.take();
        restore_mihomo_interface(mihomo_state).await;
        mark_start_error(&state).await;
        return Err(format!("写入 Fortinet 临时配置失败: {error}"));
    }
    state.inner.lock().await.fortinet_config_path = Some(temp_config_path.clone());

    if let Err(error) = state.inner().ensure_connections_allowed() {
        let _ = std::fs::remove_file(&temp_config_path);
        state.inner.lock().await.fortinet_config_path = None;
        if let Some(route_target) = gateway_route_target.as_ref() {
            remove_gateway_route(&sudo_password, route_target).await;
        }
        let mihomo_state = state.inner.lock().await.fortinet_mihomo_state.take();
        restore_mihomo_interface(mihomo_state).await;
        mark_start_error(&state).await;
        return Err(error);
    }

    let mut command = tokio::process::Command::new("sudo");
    command
        .arg("-S")
        .arg("-p")
        .arg("")
        .arg(&openfortivpn_bin)
        .arg("-c")
        .arg(&temp_config_path)
        .arg("--no-routes")
        .arg("--no-dns")
        .arg("--pppd-no-peerdns")
        .arg("--min-tls=1.0")
        .arg("--cipher-list=DHE-RSA-AES256-SHA:@SECLEVEL=0")
        .arg("-v")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    command.process_group(0);

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = std::fs::remove_file(&temp_config_path);
            state.inner.lock().await.fortinet_config_path = None;
            if let Some(route_target) = gateway_route_target.as_ref() {
                remove_gateway_route(&sudo_password, route_target).await;
            }
            let mihomo_state = state.inner.lock().await.fortinet_mihomo_state.take();
            restore_mihomo_interface(mihomo_state).await;
            mark_start_error(&state).await;
            return Err(format!("无法拉起内置 openfortivpn: {error}"));
        }
    };

    if let Err(error) = state.inner().ensure_connections_allowed() {
        if let Some(process_id) = child.id() {
            terminate_managed_process_group(&sudo_password, process_id).await;
        }
        let _ = child.kill().await;
        let _ = std::fs::remove_file(&temp_config_path);
        state.inner.lock().await.fortinet_config_path = None;
        if let Some(route_target) = gateway_route_target.as_ref() {
            remove_gateway_route(&sudo_password, route_target).await;
        }
        let mihomo_state = state.inner.lock().await.fortinet_mihomo_state.take();
        restore_mihomo_interface(mihomo_state).await;
        mark_start_error(&state).await;
        return Err(error);
    }

    let stdin_result = match child.stdin.take() {
        Some(mut stdin) => {
            stdin
                .write_all(format!("{sudo_password}\n").as_bytes())
                .await
        }
        None => Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "无法打开 openfortivpn stdin",
        )),
    };
    if let Err(error) = stdin_result {
        let _ = child.kill().await;
        let _ = std::fs::remove_file(&temp_config_path);
        state.inner.lock().await.fortinet_config_path = None;
        if let Some(route_target) = gateway_route_target.as_ref() {
            remove_gateway_route(&sudo_password, route_target).await;
        }
        let mihomo_state = state.inner.lock().await.fortinet_mihomo_state.take();
        restore_mihomo_interface(mihomo_state).await;
        mark_start_error(&state).await;
        return Err(format!("向 sudo 写入凭据失败: {error}"));
    }

    let (stdout, stderr) = match (child.stdout.take(), child.stderr.take()) {
        (Some(stdout), Some(stderr)) => (stdout, stderr),
        _ => {
            let _ = child.kill().await;
            let _ = std::fs::remove_file(&temp_config_path);
            state.inner.lock().await.fortinet_config_path = None;
            if let Some(route_target) = gateway_route_target.as_ref() {
                remove_gateway_route(&sudo_password, route_target).await;
            }
            let mihomo_state = state.inner.lock().await.fortinet_mihomo_state.take();
            restore_mihomo_interface(mihomo_state).await;
            mark_start_error(&state).await;
            return Err("无法读取内置 openfortivpn 日志".to_string());
        }
    };

    let network_watcher = tokio::spawn(maintain_split_network(
        sudo_password.clone(),
        existing_ppp_interfaces,
        custom_routes,
        primary_network,
        host.clone(),
        state.inner.clone(),
        app_handle.clone(),
    ));

    let manager = state.inner.clone();
    let watcher_app = app_handle.clone();
    let cleanup_password = sudo_password.clone();
    let temp_config_cleanup = temp_config_path.clone();
    let watcher = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let _ = tokio::fs::remove_file(&temp_config_cleanup).await;
        {
            let mut inner = manager.lock().await;
            if inner.fortinet_config_path.as_ref() == Some(&temp_config_cleanup) {
                inner.fortinet_config_path = None;
            }
        }

        tokio::join!(
            forward_logs(stdout, watcher_app.clone()),
            forward_logs(stderr, watcher_app.clone())
        );

        let (exit_status, gateway_host) = {
            let mut inner = manager.lock().await;
            let exit_status = if inner.fortinet_status == VpnStatus::Disconnecting {
                VpnStatus::Disconnected
            } else {
                VpnStatus::Error
            };
            inner.fortinet_status = exit_status;
            inner.fortinet_ip = None;
            inner.fortinet_start_time = None;
            inner.fortinet_child = None;
            if let Some(network_watcher) = inner.fortinet_network_watcher.take() {
                network_watcher.abort();
            }
            (exit_status, inner.fortinet_gateway_host.take())
        };

        if let Some(gateway_host) = gateway_host {
            remove_gateway_route(&cleanup_password, &gateway_host).await;
        }
        let mihomo_state = manager.lock().await.fortinet_mihomo_state.take();
        restore_mihomo_interface(mihomo_state).await;
        emit_status(
            &watcher_app,
            exit_status,
            if exit_status == VpnStatus::Error {
                "北京服务器 VPN 进程意外退出，请检查日志"
            } else {
                "已断开"
            },
            None,
        );
    });

    let mut child = Some(child);
    let mut watcher = Some(watcher);
    let mut network_watcher = Some(network_watcher);
    let should_abort_for_shutdown = {
        let mut inner = state.inner.lock().await;
        if state.inner().is_shutting_down() {
            true
        } else {
            inner.fortinet_child = child.take();
            inner.fortinet_watcher = watcher.take();
            inner.fortinet_network_watcher = network_watcher.take();
            false
        }
    };

    if should_abort_for_shutdown {
        if let Some(watcher) = watcher {
            watcher.abort();
        }
        if let Some(network_watcher) = network_watcher {
            network_watcher.abort();
        }
        if let Some(mut child) = child {
            if let Some(process_id) = child.id() {
                terminate_managed_process_group(&sudo_password, process_id).await;
            }
            let _ = child.kill().await;
        }
        let _ = tokio::fs::remove_file(&temp_config_path).await;
        let (gateway_target, mihomo_state) = {
            let mut inner = state.inner.lock().await;
            inner.fortinet_config_path = None;
            inner.fortinet_status = VpnStatus::Disconnected;
            inner.fortinet_start_time = None;
            inner.fortinet_ip = None;
            (
                inner.fortinet_gateway_host.take(),
                inner.fortinet_mihomo_state.take(),
            )
        };
        if let Some(gateway_target) = gateway_target {
            remove_gateway_route(&sudo_password, &gateway_target).await;
        }
        restore_mihomo_interface(mihomo_state).await;
        return Err("应用正在安全退出，已回收 Fortinet 连接进程".to_string());
    }

    Ok(())
}

/** 断开北京 Fortinet VPN，并清理本次添加的网关路由与临时配置。 */
pub async fn disconnect_fortinet_managed(
    app_handle: &AppHandle,
    manager: &VpnManager,
) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        return super::windows::disconnect(app_handle, manager, VpnType::Fortinet).await;
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = (app_handle, manager);
        return Err("当前操作系统暂不支持 Fortinet VPN 断开".to_string());
    }

    let (child, watcher, network_watcher, sudo_password, gateway_host, mihomo_state, config_path) = {
        let mut inner = manager.inner.lock().await;
        let sudo_password = inner
            .sudo_password
            .clone()
            .ok_or("断开北京服务器 VPN 前需要重新验证 macOS 系统权限")?;
        inner.fortinet_status = VpnStatus::Disconnecting;
        (
            inner.fortinet_child.take(),
            inner.fortinet_watcher.take(),
            inner.fortinet_network_watcher.take(),
            sudo_password,
            inner.fortinet_gateway_host.take(),
            inner.fortinet_mihomo_state.take(),
            inner.fortinet_config_path.take(),
        )
    };

    let has_managed_child = child.is_some();
    if let Some(mut child) = child {
        if let Some(process_id) = child.id() {
            terminate_managed_process_group(&sudo_password, process_id).await;
        }
        let _ = child.kill().await;
    }
    if let Some(watcher) = watcher {
        watcher.abort();
    }
    if let Some(network_watcher) = network_watcher {
        network_watcher.abort();
    }
    if let Some(config_path) = config_path {
        let _ = tokio::fs::remove_file(config_path).await;
    }

    if !has_managed_child {
        let _ = run_sudo_command(&sudo_password, "killall", &["openfortivpn"]).await;
    }
    if let Some(gateway_host) = gateway_host {
        remove_gateway_route(&sudo_password, &gateway_host).await;
    }
    restore_mihomo_interface(mihomo_state).await;

    {
        let mut inner = manager.inner.lock().await;
        inner.fortinet_status = VpnStatus::Disconnected;
        inner.fortinet_ip = None;
        inner.fortinet_start_time = None;
    }
    emit_status(app_handle, VpnStatus::Disconnected, "已断开", None);
    Ok(())
}

/** 提供给前端的北京 Fortinet 断开命令。 */
#[tauri::command]
pub async fn disconnect_fortinet(
    app_handle: AppHandle,
    state: tauri::State<'_, VpnManager>,
) -> Result<(), String> {
    disconnect_fortinet_managed(&app_handle, state.inner()).await
}

#[cfg(test)]
mod tests {
    use super::{
        is_mihomo_fake_ip, is_physical_interface, route_destination, route_matches_primary_network,
        routed_ipv4_destination, PrimaryNetworkState,
    };

    /** 验证 CIDR 路由可提取 route get 所需的目标地址。 */
    #[test]
    fn extracts_route_destination() {
        assert_eq!(route_destination("192.168.100.0/24"), "192.168.100.0");
    }

    /** 验证只有真实物理接口可被选为动态公网出口。 */
    #[test]
    fn identifies_physical_network_interfaces() {
        assert!(is_physical_interface("en0"));
        assert!(is_physical_interface("en10"));
        assert!(!is_physical_interface("ppp0"));
        assert!(!is_physical_interface("utun1024"));
    }

    /** 验证网关主机路由必须同时匹配当前接口和路由器。 */
    #[test]
    fn matches_current_primary_network_route() {
        let network = PrimaryNetworkState {
            interface: "en10".to_string(),
            service: "ethernet-service".to_string(),
            router: "192.168.100.1".to_string(),
        };
        let current = "gateway: 192.168.100.1\ninterface: en10\n";
        let stale = "gateway: 172.20.10.1\ninterface: en0\n";

        assert!(route_matches_primary_network(current, &network));
        assert!(!route_matches_primary_network(stale, &network));
    }

    /** 验证 Clash/Mihomo Fake-IP 网段不会被错误固定到物理网关。 */
    #[test]
    fn identifies_mihomo_fake_ip_range() {
        assert!(is_mihomo_fake_ip("198.18.0.1".parse().unwrap()));
        assert!(is_mihomo_fake_ip("198.19.255.254".parse().unwrap()));
        assert!(!is_mihomo_fake_ip("198.20.0.1".parse().unwrap()));
        assert!(!is_mihomo_fake_ip("203.0.113.10".parse().unwrap()));
    }

    /** 验证从 macOS route 输出提取实际数值目标，后续清理不再二次解析域名。 */
    #[test]
    fn extracts_routed_ipv4_destination() {
        let route = "route to: fortinet.example.com\ndestination: 198.18.0.167\ninterface: utun6\n";
        assert_eq!(
            routed_ipv4_destination(route),
            Some("198.18.0.167".parse().unwrap())
        );
    }
}
