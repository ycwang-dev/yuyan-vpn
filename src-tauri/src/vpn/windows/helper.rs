use super::ipc::{
    EngineSnapshot, HelperCommand, HelperEnvelope, HelperLog, HelperResponse, HelperSnapshot,
};
use crate::vpn::{
    classify_atrust_client_data, AtrustClientDataState, VpnConfig, VpnStatus, VpnType,
    ATRUST_CLIENT_DATA_FILE_NAME, MAX_ATRUST_CLIENT_DATA_BYTES,
};
use std::collections::VecDeque;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::ServerOptions;
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::Mutex;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::System::Console::{
    AllocConsole, GenerateConsoleCtrlEvent, GetConsoleWindow, SetConsoleCtrlHandler,
    CTRL_BREAK_EVENT,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, WaitForSingleObject, CREATE_NEW_PROCESS_GROUP, INFINITE,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_HIDE};

/** helper 单次 IPC 报文上限，避免本机恶意客户端耗尽管理员进程内存。 */
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
/** helper 最多保留的增量日志条数。 */
const MAX_LOG_LINES: usize = 1000;
/** 仅等待父进程退出所需的 Windows 进程同步访问权限。 */
const PROCESS_SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
/** Windows Fortinet 候选引擎固定的 Wintun 适配器名。 */
const FORTINET_INTERFACE: &str = "openfortivpn";
/** Windows zju-connect 固定创建的 Wintun 适配器名。 */
const ATRUST_INTERFACE: &str = "ZJU Connect";
/** 必须与 Tauri identifier 保持一致，用于限制管理员 helper 的持久化写入范围。 */
const APP_DATA_DIRECTORY: &str = "cn.yuyan.swiftvpn";
/** 当前 FortiGate 证书白名单摘要，与既有 macOS 连接策略保持一致。 */
const FORTINET_TRUSTED_CERT: &str =
    "491a5bbe4cc44c3e42141d9babfbdd29eee75aaf36401221a1dac9305c846b56";
/**
 * FortiGate 偶发在认证成功后立即重置首个会话（网关侧旧会话清理竞态），
 * 引擎会在隧道建立前退出。凭据已验证通过，自动重试不会触发账号锁定。
 */
const FORTINET_MAX_AUTO_RETRIES: u32 = 2;
/** 自动重试前等待网关清理上一个半开会话的时间。 */
const FORTINET_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(5);
/**
 * 管道只允许本机 SYSTEM、管理员和交互式登录用户访问，并把完整性标签降为 Medium。
 * 随机管道名与 128 位会话令牌仍是命令授权边界；该 ACL 只解决同一用户中/高完整性进程互通。
 */
const PIPE_SECURITY_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)S:(ML;;NW;;;ME)";

/** 持有由 Win32 分配的命名管道安全描述符，创建管道后自动释放。 */
struct PipeSecurity {
    descriptor: PSECURITY_DESCRIPTOR,
    attributes: SECURITY_ATTRIBUTES,
}

impl PipeSecurity {
    /** 从固定 SDDL 创建允许普通 UI 连接管理员 helper 的安全属性。 */
    fn new() -> Result<Self, String> {
        let sddl = PIPE_SECURITY_SDDL
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if converted == 0 || descriptor.is_null() {
            return Err(format!(
                "创建 Windows helper 管道安全描述符失败: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self {
            descriptor,
            attributes: SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            },
        })
    }

    /** 返回 Tokio 创建命名管道所需的 SECURITY_ATTRIBUTES 指针。 */
    fn as_raw(&mut self) -> *mut c_void {
        &mut self.attributes as *mut SECURITY_ATTRIBUTES as *mut c_void
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            unsafe {
                let _ = LocalFree(self.descriptor as HLOCAL);
            }
        }
    }
}

/** helper 中单个引擎的运行态；所有字段只存在管理员进程内存中。 */
struct EngineRuntime {
    status: VpnStatus,
    virtual_ip: Option<String>,
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    config_path: Option<PathBuf>,
    routes: Vec<String>,
    installed_routes: Vec<String>,
    route_gateway: Option<String>,
    interface_name: Option<String>,
    route_ready: bool,
    stack_ready: bool,
    cleanup_scheduled: bool,
}

impl Default for EngineRuntime {
    fn default() -> Self {
        Self {
            status: VpnStatus::Disconnected,
            virtual_ip: None,
            child: None,
            stdin: None,
            config_path: None,
            routes: Vec::new(),
            installed_routes: Vec::new(),
            route_gateway: None,
            interface_name: None,
            route_ready: false,
            stack_ready: false,
            cleanup_scheduled: false,
        }
    }
}

/** Fortinet 自动重试所需的连接材料与本轮进度信号；仅存于管理员进程内存。 */
struct FortinetRetryContext {
    config: VpnConfig,
    password: String,
    attempts: u32,
    authenticated: bool,
}

/** UAC helper 的完整内存状态。 */
#[derive(Default)]
struct HelperState {
    fortinet: EngineRuntime,
    atrust: EngineRuntime,
    fortinet_retry: Option<FortinetRetryContext>,
    job: Option<Arc<JobHandle>>,
    logs: VecDeque<HelperLog>,
    next_log_sequence: u64,
    auth_prompt: Option<String>,
    auth_sequence: u64,
    shutting_down: bool,
}

impl HelperState {
    /** 返回 UI 可消费的双 VPN 状态快照。 */
    fn snapshot(&self) -> HelperSnapshot {
        HelperSnapshot {
            fortinet: EngineSnapshot {
                status: self.fortinet.status,
                virtual_ip: self.fortinet.virtual_ip.clone(),
            },
            atrust: EngineSnapshot {
                status: self.atrust.status,
                virtual_ip: self.atrust.virtual_ip.clone(),
            },
            auth_prompt: self.auth_prompt.clone(),
            auth_sequence: self.auth_sequence,
        }
    }

    /** 追加一条经过脱敏的日志，并限制内存队列长度。 */
    fn push_log(&mut self, vpn_type: VpnType, text: String) {
        if should_drop_log(vpn_type, &text) {
            return;
        }
        self.next_log_sequence = self.next_log_sequence.saturating_add(1);
        self.logs.push_back(HelperLog {
            sequence: self.next_log_sequence,
            vpn_type,
            text,
        });
        while self.logs.len() > MAX_LOG_LINES {
            self.logs.pop_front();
        }
    }

    /** 返回指定序号之后的增量日志。 */
    fn logs_after(&self, sequence: u64) -> Vec<HelperLog> {
        self.logs
            .iter()
            .filter(|item| item.sequence > sequence)
            .cloned()
            .collect()
    }
}

/** RAII 持有 Job Object；helper 退出时内核会终止全部 VPN 子进程。 */
struct JobHandle(HANDLE);

unsafe impl Send for JobHandle {}
unsafe impl Sync for JobHandle {}

impl JobHandle {
    /** 创建启用 KILL_ON_JOB_CLOSE 的 Windows Job Object。 */
    fn new() -> Result<Self, String> {
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(format!(
                "创建 Windows Job Object 失败: {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            unsafe { CloseHandle(handle) };
            return Err(format!(
                "配置 Windows Job Object 失败: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self(handle))
    }

    /** 将新启动的 VPN 引擎加入当前 Job Object。 */
    fn assign(&self, child: &Child) -> Result<(), String> {
        let raw_handle = child
            .raw_handle()
            .ok_or_else(|| "无法获取 Windows VPN 子进程句柄".to_string())?;
        let assigned = unsafe { AssignProcessToJobObject(self.0, raw_handle as HANDLE) };
        if assigned == 0 {
            return Err(format!(
                "绑定 Windows VPN 子进程失败: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

impl Drop for JobHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

/** 运行无 WebView 的管理员 helper，直到 UI 父进程退出或收到 Shutdown。 */
pub async fn run(pipe_name: String, token: String, parent_pid: u32) -> Result<(), String> {
    initialize_hidden_console();
    super::append_helper_diagnostic("helper 初始化隐藏控制台完成");
    let job = Arc::new(JobHandle::new()?);
    let state = Arc::new(Mutex::new(HelperState::default()));
    state.lock().await.job = Some(job.clone());
    let (parent_exit_tx, mut parent_exit_rx) = tokio::sync::oneshot::channel::<()>();
    monitor_parent(parent_pid, parent_exit_tx)?;
    let mut pipe_security = PipeSecurity::new()?;
    super::append_helper_diagnostic("helper 中完整性命名管道 ACL 已创建");

    let mut first_instance = true;
    let mut first_client_logged = false;
    loop {
        let server = unsafe {
            ServerOptions::new()
                .first_pipe_instance(first_instance)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(&pipe_name, pipe_security.as_raw())
        }
        .map_err(|error| format!("创建 Windows helper 命名管道失败: {error}"))?;
        if first_instance {
            super::append_helper_diagnostic("helper 首个命名管道实例等待 UI 连接");
        }
        first_instance = false;

        tokio::select! {
            connected = server.connect() => {
                connected.map_err(|error| format!("接受 Windows helper 管道连接失败: {error}"))?;
                if !first_client_logged {
                    super::append_helper_diagnostic("helper 已接受普通权限 UI 管道连接");
                    first_client_logged = true;
                }
                let should_stop = handle_connection(server, &token, &state, &job).await?;
                if should_stop {
                    break;
                }
            }
            _ = &mut parent_exit_rx => {
                super::append_helper_diagnostic("UI 父进程已退出，helper 开始清理");
                break;
            }
        }
    }

    {
        let mut guard = state.lock().await;
        guard.shutting_down = true;
        guard.fortinet_retry = None;
    }
    shutdown_all(&state).await;
    super::append_helper_diagnostic("helper 已完成 VPN 子进程与路由清理");
    Ok(())
}

/** 给 helper 分配隐藏控制台，以便向独立进程组发送 CTRL_BREAK 做优雅清理。 */
fn initialize_hidden_console() {
    unsafe {
        let _ = AllocConsole();
        let _ = SetConsoleCtrlHandler(None, 1);
        let console = GetConsoleWindow();
        if !console.is_null() {
            let _ = ShowWindow(console, SW_HIDE);
        }
    }
}

/** 监控普通权限 UI 父进程；父进程消失后立即关闭 helper 与 Job Object。 */
fn monitor_parent(parent_pid: u32, sender: tokio::sync::oneshot::Sender<()>) -> Result<(), String> {
    let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE_ACCESS, 0, parent_pid) };
    if process.is_null() {
        return Err(format!(
            "无法监控 Windows UI 父进程: {}",
            std::io::Error::last_os_error()
        ));
    }
    let process_handle = process as usize;
    std::thread::spawn(move || {
        let process = process_handle as HANDLE;
        unsafe {
            let _ = WaitForSingleObject(process, INFINITE);
            CloseHandle(process);
        }
        let _ = sender.send(());
    });
    Ok(())
}

/** 读取一条长度前缀 IPC 请求并写回响应。 */
async fn handle_connection(
    mut pipe: tokio::net::windows::named_pipe::NamedPipeServer,
    token: &str,
    state: &Arc<Mutex<HelperState>>,
    job: &Arc<JobHandle>,
) -> Result<bool, String> {
    let length = pipe
        .read_u32_le()
        .await
        .map_err(|error| format!("读取 Windows helper 请求长度失败: {error}"))?
        as usize;
    if length == 0 || length > MAX_MESSAGE_BYTES {
        return Err("Windows helper 请求大小非法".to_string());
    }
    let mut payload = vec![0_u8; length];
    pipe.read_exact(&mut payload)
        .await
        .map_err(|error| format!("读取 Windows helper 请求失败: {error}"))?;
    let envelope: HelperEnvelope = serde_json::from_slice(&payload)
        .map_err(|error| format!("解析 Windows helper 请求失败: {error}"))?;

    let (response, should_stop) = if envelope.token != token {
        let snapshot = state.lock().await.snapshot();
        (
            HelperResponse::failure("Windows helper 会话令牌无效", snapshot),
            false,
        )
    } else {
        execute_command(envelope.command, state, job).await
    };

    let response_bytes = serde_json::to_vec(&response)
        .map_err(|error| format!("序列化 Windows helper 响应失败: {error}"))?;
    pipe.write_u32_le(response_bytes.len() as u32)
        .await
        .map_err(|error| format!("写入 Windows helper 响应长度失败: {error}"))?;
    pipe.write_all(&response_bytes)
        .await
        .map_err(|error| format!("写入 Windows helper 响应失败: {error}"))?;
    pipe.flush()
        .await
        .map_err(|error| format!("刷新 Windows helper 响应失败: {error}"))?;
    Ok(should_stop)
}

/** 执行一条 helper 命令并生成一致的状态/日志响应。 */
async fn execute_command(
    command: HelperCommand,
    state: &Arc<Mutex<HelperState>>,
    job: &Arc<JobHandle>,
) -> (HelperResponse, bool) {
    refresh_exited_children(state).await;
    let after_sequence = match &command {
        HelperCommand::Snapshot { after_sequence } => *after_sequence,
        HelperCommand::Ping => u64::MAX,
        _ => 0,
    };
    let result = match command {
        HelperCommand::Ping | HelperCommand::Snapshot { .. } => Ok(false),
        HelperCommand::ConnectFortinet { config, password } => {
            let previous_status = state.lock().await.fortinet.status;
            match connect_fortinet(state, job, config, password).await {
                Ok(()) => Ok(false),
                Err(error) => {
                    if !matches!(
                        previous_status,
                        VpnStatus::Connecting
                            | VpnStatus::Authenticating
                            | VpnStatus::Connected
                            | VpnStatus::Disconnecting
                    ) {
                        state.lock().await.fortinet.status = VpnStatus::Error;
                    }
                    Err(error)
                }
            }
        }
        HelperCommand::ConnectAtrust {
            config,
            password,
            client_data_path,
        } => {
            let previous_status = state.lock().await.atrust.status;
            match connect_atrust(state, job, config, password, client_data_path).await {
                Ok(()) => Ok(false),
                Err(error) => {
                    if !matches!(
                        previous_status,
                        VpnStatus::Connecting
                            | VpnStatus::Authenticating
                            | VpnStatus::Connected
                            | VpnStatus::Disconnecting
                    ) {
                        state.lock().await.atrust.status = VpnStatus::Error;
                    }
                    Err(error)
                }
            }
        }
        HelperCommand::Disconnect { vpn_type } => {
            if vpn_type == VpnType::Fortinet {
                state.lock().await.fortinet_retry = None;
            }
            disconnect_engine(state, vpn_type).await.map(|_| false)
        }
        HelperCommand::SubmitMfa { code } => submit_mfa(state, code).await.map(|_| false),
        HelperCommand::Shutdown => {
            {
                let mut guard = state.lock().await;
                guard.shutting_down = true;
                guard.fortinet_retry = None;
            }
            shutdown_all(state).await;
            Ok(true)
        }
    };

    let guard = state.lock().await;
    let snapshot = guard.snapshot();
    let logs = guard.logs_after(after_sequence);
    match result {
        Ok(should_stop) => (HelperResponse::success(snapshot, logs), should_stop),
        Err(error) => (HelperResponse::failure(error, snapshot), false),
    }
}

/** 启动 Windows openfortivpn，并把密码仅通过匿名 stdin 管道传入。 */
async fn connect_fortinet(
    state: &Arc<Mutex<HelperState>>,
    job: &Arc<JobHandle>,
    config: VpnConfig,
    password: String,
) -> Result<(), String> {
    if password.contains(['\r', '\n']) {
        return Err("Fortinet 密码不能包含换行符".to_string());
    }
    {
        let guard = state.lock().await;
        if matches!(
            guard.fortinet.status,
            VpnStatus::Connecting
                | VpnStatus::Authenticating
                | VpnStatus::Connected
                | VpnStatus::Disconnecting
        ) || guard.fortinet.child.is_some()
            || guard.fortinet.cleanup_scheduled
        {
            return Err("北京服务器 VPN 已经连接或正在连接中".to_string());
        }
    }
    {
        let mut guard = state.lock().await;
        guard.fortinet = EngineRuntime {
            status: VpnStatus::Connecting,
            routes: config.custom_routes.clone(),
            ..EngineRuntime::default()
        };
        guard.fortinet_retry = Some(FortinetRetryContext {
            config: config.clone(),
            password: password.clone(),
            attempts: 0,
            authenticated: false,
        });
    }

    let result = start_fortinet_process(state, job, config, password).await;
    if result.is_err() {
        state.lock().await.fortinet_retry = None;
    }
    result
}

/** 拉起 Windows openfortivpn 进程；调用前需已设置 Connecting 状态与路由列表。 */
async fn start_fortinet_process(
    state: &Arc<Mutex<HelperState>>,
    job: &Arc<JobHandle>,
    config: VpnConfig,
    password: String,
) -> Result<(), String> {
    let binary = engine_path("openfortivpn.exe")?;
    ensure_engine_files(&binary, true)?;
    let engine_directory = engine_directory()?;
    let runtime_directory = engine_runtime_directory()?;
    let mut command = Command::new(&binary);
    command
        .arg(format!("{}:{}", config.host, config.port))
        .arg("--json-events")
        .arg("--username")
        .arg(config.username)
        .arg(format!("--trusted-cert={FORTINET_TRUSTED_CERT}"))
        .arg("--no-routes")
        .arg("--no-dns")
        .arg("--persistent=3")
        .arg("--min-tls=1.0")
        .arg("--cipher-list=DHE-RSA-AES256-SHA:@SECLEVEL=0")
        .arg("-v")
        .current_dir(&engine_directory)
        .env("PATH", engine_runtime_path(&runtime_directory))
        .creation_flags(CREATE_NEW_PROCESS_GROUP)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|error| format!("启动 Windows openfortivpn 失败: {error}"))?;
    if let Err(error) = job.assign(&child) {
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Err(error);
    }
    let mut stdin = match child.stdin.take() {
        Some(stdin) => stdin,
        None => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err("无法打开 Windows openfortivpn 密码管道".to_string());
        }
    };
    if let Err(error) = stdin.write_all(format!("{password}\n").as_bytes()).await {
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Err(format!("写入 Fortinet 密码失败: {error}"));
    }
    if let Err(error) = stdin.flush().await {
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Err(format!("刷新 Fortinet 密码管道失败: {error}"));
    }

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    {
        let mut guard = state.lock().await;
        guard.fortinet.child = Some(child);
        guard.fortinet.stdin = Some(stdin);
    }
    spawn_log_watchers(VpnType::Fortinet, stdout, stderr, state.clone());
    Ok(())
}

/** 根据认证进度决定 Fortinet 失败后自动重试还是进入最终错误清理。 */
async fn handle_fortinet_failure(state: &Arc<Mutex<HelperState>>) {
    let retry = {
        let mut guard = state.lock().await;
        if guard.shutting_down || guard.fortinet.cleanup_scheduled {
            None
        } else {
            match guard.fortinet_retry.as_mut() {
                Some(context)
                    if context.authenticated && context.attempts < FORTINET_MAX_AUTO_RETRIES =>
                {
                    context.attempts += 1;
                    Some((
                        context.config.clone(),
                        context.password.clone(),
                        context.attempts,
                    ))
                }
                _ => None,
            }
        }
    };
    let Some((config, password, attempt)) = retry else {
        schedule_error_cleanup(state.clone(), VpnType::Fortinet).await;
        return;
    };

    state.lock().await.push_log(
        VpnType::Fortinet,
        format!(
            "Fortinet 引擎在隧道就绪前退出（网关重置旧会话），{} 秒后自动重试（第 {attempt}/{FORTINET_MAX_AUTO_RETRIES} 次）",
            FORTINET_RETRY_DELAY.as_secs()
        ),
    );
    // 回收残留进程与路由，随后恢复为对 UI 可见的连接中状态。
    let _ = disconnect_engine(state, VpnType::Fortinet).await;
    {
        let mut guard = state.lock().await;
        if guard.shutting_down || guard.fortinet_retry.is_none() {
            return;
        }
        guard.fortinet = EngineRuntime {
            status: VpnStatus::Connecting,
            routes: config.custom_routes.clone(),
            ..EngineRuntime::default()
        };
    }

    let retry_state = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(FORTINET_RETRY_DELAY).await;
        let job = {
            let guard = retry_state.lock().await;
            let still_waiting = !guard.shutting_down
                && guard.fortinet_retry.is_some()
                && guard.fortinet.status == VpnStatus::Connecting
                && guard.fortinet.child.is_none()
                && !guard.fortinet.cleanup_scheduled;
            if still_waiting {
                guard.job.clone()
            } else {
                None
            }
        };
        let Some(job) = job else {
            return;
        };
        if let Err(error) = start_fortinet_process(&retry_state, &job, config, password).await {
            let mut guard = retry_state.lock().await;
            guard.push_log(
                VpnType::Fortinet,
                format!("自动重试拉起 Fortinet 引擎失败: {error}"),
            );
            guard.fortinet_retry = None;
            guard.fortinet.status = VpnStatus::Error;
        }
    });
}

/** 启动 Windows zju-connect；敏感 TOML 只写入当前用户临时目录并快速删除。 */
async fn connect_atrust(
    state: &Arc<Mutex<HelperState>>,
    job: &Arc<JobHandle>,
    config: VpnConfig,
    password: String,
    client_data_path: PathBuf,
) -> Result<(), String> {
    {
        let guard = state.lock().await;
        if matches!(
            guard.atrust.status,
            VpnStatus::Connecting
                | VpnStatus::Authenticating
                | VpnStatus::Connected
                | VpnStatus::Disconnecting
        ) || guard.atrust.child.is_some()
            || guard.atrust.cleanup_scheduled
        {
            return Err("长沙服务器 VPN 已经连接或正在连接中".to_string());
        }
    }
    {
        let mut guard = state.lock().await;
        guard.auth_prompt = None;
        guard.atrust = EngineRuntime {
            status: VpnStatus::Connecting,
            interface_name: Some(ATRUST_INTERFACE.to_string()),
            ..EngineRuntime::default()
        };
    }

    let binary = engine_path("zju-connect.exe")?;
    ensure_engine_files(&binary, true)?;
    let engine_directory = engine_directory()?;
    let runtime_directory = engine_runtime_directory()?;
    let prepared_client_data = prepare_atrust_client_data(&client_data_path).await?;
    state.lock().await.push_log(
        VpnType::Atrust,
        atrust_client_data_log(&prepared_client_data).to_string(),
    );
    let config_path = unique_temp_path("atrust", "toml");
    let toml = build_atrust_config(&config, &password, &client_data_path);
    let mut config_file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&config_path)
        .map_err(|error| format!("创建 Windows aTrust 临时配置失败: {error}"))?;
    if let Err(error) = restrict_private_path_access(&config_path, "VPN 临时配置").await {
        drop(config_file);
        let _ = std::fs::remove_file(&config_path);
        return Err(error);
    }
    if let Err(error) = std::io::Write::write_all(&mut config_file, toml.as_bytes()) {
        drop(config_file);
        let _ = std::fs::remove_file(&config_path);
        return Err(format!("写入 Windows aTrust 临时配置失败: {error}"));
    }
    drop(config_file);

    let mut command = Command::new(&binary);
    command
        .arg("-config")
        .arg(&config_path)
        .current_dir(&engine_directory)
        .env("PATH", engine_runtime_path(&runtime_directory))
        .env("YUYAN_VPN_EMBEDDED_CAPTCHA", "1")
        .creation_flags(CREATE_NEW_PROCESS_GROUP)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = std::fs::remove_file(&config_path);
            return Err(format!("启动 Windows zju-connect 失败: {error}"));
        }
    };
    if let Err(error) = job.assign(&child) {
        let _ = child.kill().await;
        let _ = child.wait().await;
        let _ = std::fs::remove_file(&config_path);
        return Err(error);
    }
    let stdin = match child.stdin.take() {
        Some(stdin) => stdin,
        None => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            let _ = std::fs::remove_file(&config_path);
            return Err("无法打开 Windows zju-connect MFA 管道".to_string());
        }
    };
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    {
        let mut guard = state.lock().await;
        guard.atrust.child = Some(child);
        guard.atrust.stdin = Some(stdin);
        guard.atrust.config_path = Some(config_path.clone());
    }
    spawn_log_watchers(VpnType::Atrust, stdout, stderr, state.clone());
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let _ = tokio::fs::remove_file(&config_path).await;
        let mut guard = cleanup_state.lock().await;
        if guard.atrust.config_path.as_ref() == Some(&config_path) {
            guard.atrust.config_path = None;
        }
    });
    Ok(())
}

/** 为 stdout/stderr 建立合并日志监控，不让任一满管道阻塞 VPN 引擎。 */
fn spawn_log_watchers(
    vpn_type: VpnType,
    stdout: Option<tokio::process::ChildStdout>,
    stderr: Option<tokio::process::ChildStderr>,
    state: Arc<Mutex<HelperState>>,
) {
    tokio::spawn(async move {
        let stdout_task = async {
            if let Some(stdout) = stdout {
                forward_lines(vpn_type, stdout, state.clone()).await;
            }
        };
        let stderr_task = async {
            if let Some(stderr) = stderr {
                forward_lines(vpn_type, stderr, state.clone()).await;
            }
        };
        tokio::join!(stdout_task, stderr_task);
        refresh_exited_children(&state).await;
    });
}

/** 逐行读取并解析单个引擎日志流。 */
async fn forward_lines<R>(vpn_type: VpnType, reader: R, state: Arc<Mutex<HelperState>>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(text)) = lines.next_line().await {
        handle_engine_log(vpn_type, text, &state).await;
    }
}

/** 将结构化 Fortinet 事件和 aTrust 文本日志转换为统一状态。 */
async fn handle_engine_log(vpn_type: VpnType, text: String, state: &Arc<Mutex<HelperState>>) {
    match vpn_type {
        VpnType::Fortinet => handle_fortinet_log(&text, state).await,
        VpnType::Atrust => handle_atrust_log(&text, state).await,
    }
    state.lock().await.push_log(vpn_type, text);
}

/** 处理 openfortivpn 的 JSON 事件，并在 Wintun 就绪后安装精确北京分流路由。 */
async fn handle_fortinet_log(text: &str, state: &Arc<Mutex<HelperState>>) {
    if text.contains("Authenticated.") || text.contains("Remote gateway has allocated a VPN") {
        if let Some(context) = state.lock().await.fortinet_retry.as_mut() {
            context.authenticated = true;
        }
    }
    let Ok(event) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    match event.get("event").and_then(serde_json::Value::as_str) {
        Some("tunnel_up") => {
            let Some(ip) = event
                .get("local_ip")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
            else {
                return;
            };
            if ip.parse::<std::net::Ipv4Addr>().is_err() {
                state
                    .lock()
                    .await
                    .push_log(VpnType::Fortinet, "Fortinet 返回了非法虚拟 IP".to_string());
                schedule_error_cleanup(state.clone(), VpnType::Fortinet).await;
                return;
            }
            let routes = state.lock().await.fortinet.routes.clone();
            match install_fortinet_routes(&routes, &ip).await {
                Ok(installed) => {
                    let mut guard = state.lock().await;
                    guard.fortinet.virtual_ip = Some(ip.clone());
                    guard.fortinet.route_gateway = Some(ip);
                    guard.fortinet.installed_routes = installed;
                    guard.fortinet.status = VpnStatus::Connected;
                    // 隧道成功建立，此后的中断视为新一轮故障，重置重试预算。
                    if let Some(context) = guard.fortinet_retry.as_mut() {
                        context.attempts = 0;
                        context.authenticated = true;
                    }
                }
                Err(error) => {
                    let mut guard = state.lock().await;
                    guard.fortinet.status = VpnStatus::Error;
                    guard.push_log(VpnType::Fortinet, error);
                    drop(guard);
                    schedule_error_cleanup(state.clone(), VpnType::Fortinet).await;
                }
            }
        }
        Some("state_change") => {
            let state_name = event
                .get("state")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let mut guard = state.lock().await;
            // 引擎仅在认证并取得 VPN 配置后才进入 connected，可作为安全重试信号。
            if state_name == "connected" {
                if let Some(context) = guard.fortinet_retry.as_mut() {
                    context.authenticated = true;
                }
            }
            if guard.fortinet.status != VpnStatus::Error {
                guard.fortinet.status = match state_name {
                    "disconnecting" => VpnStatus::Disconnecting,
                    "connected" if guard.fortinet.virtual_ip.is_some() => VpnStatus::Connected,
                    _ => VpnStatus::Connecting,
                };
            }
        }
        Some("cert_error") => {
            state.lock().await.fortinet.status = VpnStatus::Error;
            schedule_error_cleanup(state.clone(), VpnType::Fortinet).await;
        }
        Some("error") => {
            handle_fortinet_failure(state).await;
        }
        Some("transport_down") => {
            if let Some(reason) = event.get("reason").and_then(serde_json::Value::as_str) {
                state.lock().await.push_log(
                    VpnType::Fortinet,
                    format!("Fortinet 传输层停止原因: {reason}"),
                );
            }
        }
        Some("tunnel_down") => {
            let (routes, gateway) = {
                let mut guard = state.lock().await;
                let will_reconnect =
                    guard.fortinet.child.is_some() && !guard.fortinet.cleanup_scheduled;
                guard.fortinet.status = if will_reconnect {
                    VpnStatus::Connecting
                } else {
                    VpnStatus::Disconnected
                };
                guard.fortinet.virtual_ip = None;
                (
                    std::mem::take(&mut guard.fortinet.installed_routes),
                    guard.fortinet.route_gateway.take(),
                )
            };
            remove_fortinet_routes(&routes, gateway.as_deref()).await;
        }
        _ => {}
    }
}

/** 处理 zju-connect 的连接、路由和 MFA 关键日志。 */
async fn handle_atrust_log(text: &str, state: &Arc<Mutex<HelperState>>) {
    let lower = text.to_lowercase();
    let route_to_install = text
        .split_once("Add route to ")
        .map(|(_, value)| value.trim().to_string())
        .filter(|value| is_valid_ipv4_cidr(value));
    let mut should_cleanup = false;
    {
        let mut guard = state.lock().await;
        if let Some((_, value)) = text.split_once("Received IP:") {
            let ip = value.trim();
            if ip.parse::<std::net::Ipv4Addr>().is_ok() {
                guard.atrust.virtual_ip = Some(ip.to_string());
                guard.atrust.route_gateway = Some(ip.to_string());
            }
        }
        if let Some((_, value)) = text.split_once("Interface Name:") {
            let interface_name = value.split(',').next().unwrap_or_default().trim();
            if !interface_name.is_empty() {
                guard.atrust.interface_name = Some(interface_name.to_string());
            }
        }
        if text.contains("Use DNS server ") || text.contains("No DNS server provided by server") {
            guard.atrust.stack_ready = true;
        }
        if text.contains("http://127.0.0.1:") {
            guard.atrust.status = VpnStatus::Authenticating;
        } else if is_mfa_prompt(text) {
            guard.atrust.status = VpnStatus::Authenticating;
            guard.auth_prompt = Some(text.to_string());
            guard.auth_sequence = guard.auth_sequence.saturating_add(1);
        } else if lower.contains("incorrect password")
            || lower.contains("vpn client setup error")
            || lower.contains("login error:")
            || lower.contains("tun stack setup error")
        {
            guard.atrust.status = VpnStatus::Error;
            should_cleanup = true;
        }
    }

    if let Some(route) = route_to_install {
        let gateway = state.lock().await.atrust.route_gateway.clone();
        if let Some(gateway) = gateway {
            match install_atrust_route(&route, &gateway).await {
                Ok(()) => {
                    let mut guard = state.lock().await;
                    if !guard.atrust.installed_routes.contains(&route) {
                        guard.atrust.installed_routes.push(route);
                    }
                    guard.atrust.route_ready = true;
                }
                Err(error) => {
                    let mut guard = state.lock().await;
                    guard.atrust.status = VpnStatus::Error;
                    guard.push_log(VpnType::Atrust, error);
                    should_cleanup = true;
                }
            }
        }
    }

    {
        let mut guard = state.lock().await;
        if guard.atrust.status != VpnStatus::Error
            && guard.atrust.virtual_ip.is_some()
            && guard.atrust.interface_name.is_some()
            && guard.atrust.route_ready
            && guard.atrust.stack_ready
        {
            guard.atrust.status = VpnStatus::Connected;
        }
    }
    if should_cleanup {
        schedule_error_cleanup(state.clone(), VpnType::Atrust).await;
    }
}

/** 给 zju-connect 当前 stdin 写入短信码/TOTP。 */
async fn submit_mfa(state: &Arc<Mutex<HelperState>>, code: String) -> Result<(), String> {
    if code.contains(['\r', '\n']) || code.trim().is_empty() {
        return Err("二次验证码格式非法".to_string());
    }
    let mut stdin = {
        let mut guard = state.lock().await;
        guard
            .atrust
            .stdin
            .take()
            .ok_or_else(|| "当前没有等待二次认证的 Windows aTrust 会话".to_string())?
    };
    let result = stdin
        .write_all(format!("{}\n", code.trim()).as_bytes())
        .await
        .map_err(|error| format!("写入 Windows aTrust 二次验证码失败: {error}"));
    state.lock().await.atrust.stdin = Some(stdin);
    result
}

/** 优雅终止单个独立进程组，超时后再强制结束。 */
async fn disconnect_engine(
    state: &Arc<Mutex<HelperState>>,
    vpn_type: VpnType,
) -> Result<(), String> {
    let (mut child, routes, gateway, config_path) = {
        let mut guard = state.lock().await;
        let engine = match vpn_type {
            VpnType::Fortinet => &mut guard.fortinet,
            VpnType::Atrust => &mut guard.atrust,
        };
        engine.status = VpnStatus::Disconnecting;
        (
            engine.child.take(),
            std::mem::take(&mut engine.installed_routes),
            engine.route_gateway.take(),
            engine.config_path.take(),
        )
    };

    if let Some(child_ref) = child.as_mut() {
        if let Some(pid) = child_ref.id() {
            unsafe {
                let _ = GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid);
            }
        }
        let graceful =
            tokio::time::timeout(std::time::Duration::from_secs(6), child_ref.wait()).await;
        if graceful.is_err() {
            let _ = child_ref.kill().await;
            let _ = child_ref.wait().await;
        }
    }
    if vpn_type == VpnType::Fortinet {
        remove_fortinet_routes(&routes, gateway.as_deref()).await;
    } else {
        remove_atrust_routes(&routes, gateway.as_deref()).await;
    }
    if let Some(path) = config_path {
        let _ = tokio::fs::remove_file(path).await;
    }

    let mut guard = state.lock().await;
    let engine = match vpn_type {
        VpnType::Fortinet => &mut guard.fortinet,
        VpnType::Atrust => &mut guard.atrust,
    };
    *engine = EngineRuntime::default();
    if vpn_type == VpnType::Atrust {
        guard.auth_prompt = None;
    }
    Ok(())
}

/** 在错误状态下只调度一次优雅进程、路由和临时文件清理，最终保留 Error 供 UI 展示。 */
async fn schedule_error_cleanup(state: Arc<Mutex<HelperState>>, vpn_type: VpnType) {
    let should_schedule = {
        let mut guard = state.lock().await;
        let engine = match vpn_type {
            VpnType::Fortinet => &mut guard.fortinet,
            VpnType::Atrust => &mut guard.atrust,
        };
        let should_schedule = if engine.cleanup_scheduled {
            false
        } else {
            engine.cleanup_scheduled = true;
            engine.status = VpnStatus::Error;
            true
        };
        if vpn_type == VpnType::Fortinet {
            guard.fortinet_retry = None;
        }
        should_schedule
    };
    if !should_schedule {
        return;
    }
    tokio::spawn(async move {
        let _ = disconnect_engine(&state, vpn_type).await;
        let mut guard = state.lock().await;
        let engine = match vpn_type {
            VpnType::Fortinet => &mut guard.fortinet,
            VpnType::Atrust => &mut guard.atrust,
        };
        engine.status = VpnStatus::Error;
    });
}

/** 终止双 VPN；供显式 Shutdown 和父进程异常退出共同复用。 */
async fn shutdown_all(state: &Arc<Mutex<HelperState>>) {
    let _ = disconnect_engine(state, VpnType::Fortinet).await;
    let _ = disconnect_engine(state, VpnType::Atrust).await;
}

/** 清理已经自行退出的 Child 句柄并更新状态。 */
async fn refresh_exited_children(state: &Arc<Mutex<HelperState>>) {
    for vpn_type in [VpnType::Fortinet, VpnType::Atrust] {
        let previous_status = {
            let mut guard = state.lock().await;
            let engine = match vpn_type {
                VpnType::Fortinet => &mut guard.fortinet,
                VpnType::Atrust => &mut guard.atrust,
            };
            let exited = engine
                .child
                .as_mut()
                .and_then(|child| child.try_wait().ok().flatten())
                .is_some();
            exited.then_some(engine.status)
        };
        if let Some(previous_status) = previous_status {
            // Fortinet 进程在隧道就绪前意外退出时，由重试仲裁决定自动重连或错误清理。
            if vpn_type == VpnType::Fortinet && previous_status != VpnStatus::Disconnecting {
                handle_fortinet_failure(state).await;
                continue;
            }
            let _ = disconnect_engine(state, vpn_type).await;
            if previous_status != VpnStatus::Disconnecting {
                let mut guard = state.lock().await;
                let engine = match vpn_type {
                    VpnType::Fortinet => &mut guard.fortinet,
                    VpnType::Atrust => &mut guard.atrust,
                };
                engine.status = VpnStatus::Error;
            }
        }
    }
}

/** 使用 netsh 在 openfortivpn Wintun 上安装精确 CIDR 路由。 */
async fn install_fortinet_routes(routes: &[String], gateway: &str) -> Result<Vec<String>, String> {
    let mut installed = Vec::new();
    for route in routes {
        let mut added = false;
        for _ in 0..50 {
            let _ = run_netsh_route("delete", route, gateway).await;
            if run_netsh_route("add", route, gateway).await?.success() {
                added = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        if !added {
            remove_fortinet_routes(&installed, Some(gateway)).await;
            return Err(format!("安装 Windows 北京内网路由失败: {route}"));
        }
        installed.push(route.clone());
    }
    Ok(installed)
}

/** 删除本会话实际添加的 Fortinet 路由。 */
async fn remove_fortinet_routes(routes: &[String], gateway: Option<&str>) {
    let Some(gateway) = gateway else {
        return;
    };
    for route in routes {
        let _ = run_netsh_route("delete", route, gateway).await;
    }
}

/** 复核并接管 zju-connect 输出的单条服务端资源路由。 */
async fn install_atrust_route(route: &str, gateway: &str) -> Result<(), String> {
    for _ in 0..30 {
        let _ =
            run_netsh_route_for_interface("delete", route, ATRUST_INTERFACE, Some(gateway)).await;
        if run_netsh_route_for_interface("add", route, ATRUST_INTERFACE, Some(gateway))
            .await?
            .success()
        {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Err(format!("安装 Windows 长沙内网路由失败: {route}"))
}

/** 删除 helper 本次复核的 aTrust 资源路由和 zju-connect 的低优先级默认路由。 */
async fn remove_atrust_routes(routes: &[String], gateway: Option<&str>) {
    let Some(gateway) = gateway else {
        return;
    };
    for route in routes.iter().map(String::as_str).chain(["0.0.0.0/0"]) {
        let _ =
            run_netsh_route_for_interface("delete", route, ATRUST_INTERFACE, Some(gateway)).await;
    }
}

/** 执行单条语言无关的 Windows netsh active-store 路由命令。 */
async fn run_netsh_route(
    action: &str,
    route: &str,
    gateway: &str,
) -> Result<std::process::ExitStatus, String> {
    run_netsh_route_for_interface(action, route, FORTINET_INTERFACE, Some(gateway)).await
}

/** 对固定接口执行参数化 netsh 路由命令，不经 shell 解释服务器下发值。 */
async fn run_netsh_route_for_interface(
    action: &str,
    route: &str,
    interface_name: &str,
    gateway: Option<&str>,
) -> Result<std::process::ExitStatus, String> {
    let mut args = vec![
        "interface".to_string(),
        "ipv4".to_string(),
        action.to_string(),
        "route".to_string(),
        format!("prefix={route}"),
        format!("interface={interface_name}"),
    ];
    if let Some(gateway) = gateway {
        args.push(format!("nexthop={gateway}"));
    }
    args.push("store=active".to_string());
    Command::new("netsh.exe")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|error| format!("执行 Windows 分流路由命令失败: {error}"))
}

/** 只接受非默认 IPv4 CIDR，避免把异常服务端日志转成危险的系统路由。 */
fn is_valid_ipv4_cidr(route: &str) -> bool {
    let Some((address, prefix)) = route.split_once('/') else {
        return false;
    };
    address.parse::<std::net::Ipv4Addr>().is_ok()
        && prefix
            .parse::<u8>()
            .map(|value| (1..=32).contains(&value))
            .unwrap_or(false)
}

/** Windows 启动前得到的 aTrust 客户端登录态检查结果。 */
struct PreparedAtrustClientData {
    state: AtrustClientDataState,
    reset_invalid: bool,
}

/** 返回 Windows 普通 UI 进程唯一允许 helper 写入的 aTrust 登录状态路径。 */
fn expected_atrust_client_data_path() -> Result<PathBuf, String> {
    let roaming_data = std::env::var_os("APPDATA").ok_or_else(|| {
        "无法确定 Windows 当前用户数据目录，已拒绝持久化 aTrust 登录状态".to_string()
    })?;
    Ok(PathBuf::from(roaming_data)
        .join(APP_DATA_DIRECTORY)
        .join(".runtime")
        .join(ATRUST_CLIENT_DATA_FILE_NAME))
}

/** 检查 Windows 路径是否包含可能让管理员写入越界的重解析点。 */
fn is_windows_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/** 校验并按层创建普通目录，禁止通过 junction/symlink 改写管理员 helper 目标。 */
fn ensure_plain_directory(path: &Path, label: &str) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || is_windows_reparse_point(&metadata) {
                return Err(format!("{label}不是安全的普通目录"));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(path).map_err(|error| format!("创建{label}失败: {error}"))?;
        }
        Err(error) => return Err(format!("检查{label}失败: {error}")),
    }
    Ok(())
}

/**
 * 创建或校验 Windows aTrust 客户端数据文件，并用 ACL 限定当前用户与系统管理员。
 */
async fn prepare_atrust_client_data(path: &Path) -> Result<PreparedAtrustClientData, String> {
    let expected_path = expected_atrust_client_data_path()?;
    if !path
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected_path.to_string_lossy())
    {
        return Err("Windows aTrust 登录状态路径超出应用数据目录，已拒绝连接".to_string());
    }

    let app_directory = expected_path
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| "Windows aTrust 登录状态路径不完整".to_string())?;
    let runtime_directory = expected_path
        .parent()
        .ok_or_else(|| "Windows aTrust 登录状态路径缺少运行目录".to_string())?;
    ensure_plain_directory(app_directory, " Windows 应用数据目录")?;
    ensure_plain_directory(runtime_directory, " Windows aTrust 登录状态目录")?;
    restrict_private_path_access(runtime_directory, "aTrust 登录状态目录").await?;

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("检查 Windows aTrust 登录状态文件失败: {error}")),
    };
    let Some(metadata) = metadata else {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|error| format!("创建 Windows aTrust 登录状态文件失败: {error}"))?;
        if let Err(error) = restrict_private_path_access(path, "aTrust 登录状态文件").await {
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
        std::io::Write::write_all(&mut file, b"{}")
            .map_err(|error| format!("初始化 Windows aTrust 登录状态文件失败: {error}"))?;
        return Ok(PreparedAtrustClientData {
            state: AtrustClientDataState::Empty,
            reset_invalid: false,
        });
    };

    if !metadata.is_file() || is_windows_reparse_point(&metadata) {
        return Err("Windows aTrust 登录状态文件不是安全的普通文件".to_string());
    }
    restrict_private_path_access(path, "aTrust 登录状态文件").await?;
    if metadata.len() <= MAX_ATRUST_CLIENT_DATA_BYTES {
        let content = std::fs::read(path)
            .map_err(|error| format!("读取 Windows aTrust 登录状态文件失败: {error}"))?;
        if let Some(state) = classify_atrust_client_data(&content) {
            return Ok(PreparedAtrustClientData {
                state,
                reset_invalid: false,
            });
        }
    }

    std::fs::write(path, b"{}")
        .map_err(|error| format!("重置损坏的 Windows aTrust 登录状态文件失败: {error}"))?;
    Ok(PreparedAtrustClientData {
        state: AtrustClientDataState::Empty,
        reset_invalid: true,
    })
}

/** 生成不包含 Cookie、设备 ID 或本地路径的登录态复用日志。 */
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

/** 生成仅持久化 Cookie 与设备 ID、不复用资源数据的 aTrust TOML。 */
fn build_atrust_config(config: &VpnConfig, password: &str, client_data_path: &Path) -> String {
    format!(
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
debug_dump = false
auth_type = "auth/psw"
login_domain = "local"
client_data_file = "{}"
"#,
        toml_escape(&config.host),
        config.port,
        toml_escape(&config.username),
        toml_escape(password),
        toml_escape(&client_data_path.to_string_lossy()),
    )
}

/** TOML 基本字符串转义，阻止凭据逃逸到额外配置项。 */
fn toml_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/** 返回与应用主程序同目录的 Windows 引擎路径。 */
fn engine_path(name: &str) -> Result<PathBuf, String> {
    Ok(engine_directory()?.join(name))
}

/** 返回 Windows 安装目录；两个 sidecar 必须位于此目录。 */
fn engine_directory() -> Result<PathBuf, String> {
    std::env::current_exe()
        .map_err(|error| format!("获取 Windows 应用路径失败: {error}"))?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "Windows 应用路径缺少父目录".to_string())
}

/** 返回随安装包部署的 Wintun、MinGW DLL 与许可证资源目录。 */
fn engine_runtime_directory() -> Result<PathBuf, String> {
    Ok(engine_directory()?.join("binaries").join("windows-runtime"))
}

/** 将 VPN 运行库目录置于子进程 PATH 首位，避免加载系统中的同名 DLL。 */
fn engine_runtime_path(runtime_directory: &Path) -> std::ffi::OsString {
    let mut paths = vec![runtime_directory.to_path_buf()];
    if let Ok(directory) = engine_directory() {
        paths.push(directory);
    }
    if let Some(existing) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&existing));
    }
    std::env::join_paths(paths).unwrap_or_else(|_| runtime_directory.as_os_str().to_os_string())
}

/** 校验引擎与官方 Wintun DLL 确实进入安装目录。 */
fn ensure_engine_files(binary: &Path, require_wintun: bool) -> Result<(), String> {
    if !binary.is_file() {
        return Err(format!("Windows 安装包缺少 VPN 引擎: {}", binary.display()));
    }
    if require_wintun {
        let wintun = engine_directory()?.join("wintun.dll");
        if !wintun.is_file() {
            return Err(format!(
                "Windows 安装包缺少主程序同级官方 Wintun: {}",
                wintun.display()
            ));
        }
    }
    Ok(())
}

/** 创建不含账号信息的随机临时文件名。 */
fn unique_temp_path(prefix: &str, extension: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "yuyan-{prefix}-{}-{nonce}.{extension}",
        std::process::id()
    ))
}

/** 移除文件或目录的继承权限，只允许当前用户、SYSTEM 与管理员访问。 */
async fn restrict_private_path_access(path: &Path, label: &str) -> Result<(), String> {
    let username = std::env::var("USERNAME")
        .map_err(|_| format!("无法确定 Windows 当前用户，已拒绝访问{label}"))?;
    let domain = std::env::var("USERDOMAIN").unwrap_or_default();
    let principal = if domain.is_empty() {
        username
    } else {
        format!("{domain}\\{username}")
    };
    let permission = if path.is_dir() { "(OI)(CI)(F)" } else { "(F)" };
    let status = Command::new("icacls.exe")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("{principal}:{permission}"))
        .arg("/grant:r")
        .arg(format!("*S-1-5-18:{permission}"))
        .arg("/grant:r")
        .arg(format!("*S-1-5-32-544:{permission}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|error| format!("限制 Windows {label}权限失败: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("限制 Windows {label}权限失败，已停止连接"))
    }
}

/** 过滤 cookie、会话材料和高噪声数据包日志。 */
fn should_drop_log(vpn_type: VpnType, text: &str) -> bool {
    let lower = text.to_lowercase();
    [
        "cookie:",
        "loaded password",
        "configuration password",
        "client data saved to",
        "client data file",
    ]
    .iter()
    .any(|keyword| lower.contains(keyword))
        || (vpn_type == VpnType::Atrust
            && [
                "given auth data",
                "received client resource",
                "sid:",
                "signkey:",
            ]
            .iter()
            .any(|keyword| lower.contains(keyword)))
        || (vpn_type == VpnType::Fortinet
            && [
                "pppd ---> gateway",
                "gateway ---> pppd",
                "tun ---> gateway",
                "gateway ---> tun",
            ]
            .iter()
            .any(|keyword| lower.contains(keyword)))
}

/** 判断 zju-connect 是否正在同步等待短信码/TOTP。 */
fn is_mfa_prompt(text: &str) -> bool {
    let lower = text.to_lowercase();
    [
        "please enter the sms verification code",
        "please enter your sms code",
        "please enter your totp code",
        "请输入短信验证码",
        "请输入二次验证码",
        "请输入 totp 验证码",
    ]
    .iter()
    .any(|prompt| lower.contains(prompt))
}

#[cfg(test)]
mod tests {
    use super::{
        build_atrust_config, is_valid_ipv4_cidr, should_drop_log, toml_escape, HelperState,
        PIPE_SECURITY_SDDL,
    };
    use crate::vpn::{VpnConfig, VpnType};
    use std::path::Path;

    /** 管道 ACL 必须同时保留本机身份限制与 Medium 完整性标签。 */
    #[test]
    fn pipe_security_allows_medium_integrity_local_ui() {
        assert!(PIPE_SECURITY_SDDL.contains("(A;;GA;;;SY)"));
        assert!(PIPE_SECURITY_SDDL.contains("(A;;GA;;;BA)"));
        assert!(PIPE_SECURITY_SDDL.contains("(A;;GA;;;IU)"));
        assert!(PIPE_SECURITY_SDDL.contains("S:(ML;;NW;;;ME)"));
    }

    /** 服务端日志只有合法的非默认 IPv4 CIDR 才能进入 netsh 参数。 */
    #[test]
    fn validates_server_route_cidr() {
        assert!(is_valid_ipv4_cidr("192.168.100.0/24"));
        assert!(is_valid_ipv4_cidr("192.168.111.64/32"));
        assert!(!is_valid_ipv4_cidr("0.0.0.0/0"));
        assert!(!is_valid_ipv4_cidr("192.168.1.1 & whoami/32"));
    }

    /** aTrust 临时 TOML 中的凭据不能逃逸为额外配置项。 */
    #[test]
    fn escapes_atrust_toml_value() {
        assert_eq!(toml_escape("a\\b\"c\nd\r"), "a\\\\b\\\"c\\nd\\r");
    }

    /** aTrust 配置只引用受限客户端数据文件，不持久化 SID 或服务端资源。 */
    #[test]
    fn persists_only_atrust_client_auth_data() {
        let config = VpnConfig {
            enabled: true,
            host: "vpn.example.edu".to_string(),
            port: 443,
            username: "alice".to_string(),
            password: None,
            save_password: false,
            custom_routes: Vec::new(),
        };
        let toml = build_atrust_config(
            &config,
            "password",
            Path::new(
                r"C:\Users\alice\AppData\Roaming\cn.yuyan.swiftvpn\.runtime\atrust-client-data.json",
            ),
        );

        assert!(toml.contains("client_data_file = \"C:\\\\Users\\\\alice"));
        assert!(!toml.contains("resource_file"));
        assert!(!toml.contains("sid ="));
        assert!(!toml.contains("device_id ="));
    }

    /** 敏感客户端路径与 Fortinet 逐包日志不得进入管理员 helper 的持久队列。 */
    #[test]
    fn drops_sensitive_or_noisy_helper_logs() {
        assert!(should_drop_log(
            VpnType::Fortinet,
            "DEBUG: tun ---> gateway (128 bytes)"
        ));
        assert!(should_drop_log(
            VpnType::Fortinet,
            "DEBUG: gateway ---> pppd (64 bytes)"
        ));
        assert!(!should_drop_log(
            VpnType::Fortinet,
            "INFO: Tunnel is up and running."
        ));
        assert!(should_drop_log(
            VpnType::Atrust,
            r"Client data saved to C:\Users\alice\atrust-client-data.json"
        ));
    }

    /** 快照只返回 UI 已确认序号之后的新日志。 */
    #[test]
    fn returns_incremental_helper_logs() {
        let mut state = HelperState::default();
        state.push_log(VpnType::Fortinet, "first".to_string());
        state.push_log(VpnType::Fortinet, "second".to_string());

        let logs = state.logs_after(1);
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].sequence, 2);
        assert_eq!(logs[0].text, "second");
        assert!(state.logs_after(u64::MAX).is_empty());
    }
}
