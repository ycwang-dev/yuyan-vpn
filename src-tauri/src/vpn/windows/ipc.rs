use crate::vpn::{VpnConfig, VpnStatus, VpnType};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/** Windows UAC helper 的内部启动参数。 */
pub const HELPER_ARGUMENT: &str = "--yuyan-vpn-helper";

/** 普通权限 UI 发给管理员 helper 的控制命令。 */
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum HelperCommand {
    Ping,
    ConnectFortinet {
        config: VpnConfig,
        password: String,
    },
    ConnectAtrust {
        config: VpnConfig,
        password: String,
        client_data_path: PathBuf,
    },
    Disconnect {
        vpn_type: VpnType,
    },
    SubmitMfa {
        code: String,
    },
    Snapshot {
        after_sequence: u64,
    },
    Shutdown,
}

/** 每条命令都携带当前 helper 会话令牌，拒绝其他本机管道客户端。 */
#[derive(Debug, Serialize, Deserialize)]
pub struct HelperEnvelope {
    pub token: String,
    pub command: HelperCommand,
}

/** 单个 Windows VPN 引擎的可序列化状态。 */
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EngineSnapshot {
    pub status: VpnStatus,
    pub virtual_ip: Option<String>,
}

impl Default for EngineSnapshot {
    fn default() -> Self {
        Self {
            status: VpnStatus::Disconnected,
            virtual_ip: None,
        }
    }
}

/** Windows helper 的双 VPN 状态快照。 */
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HelperSnapshot {
    pub fortinet: EngineSnapshot,
    pub atrust: EngineSnapshot,
    pub auth_prompt: Option<String>,
    pub auth_sequence: u64,
}

/** helper 中经过脱敏的增量日志。 */
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HelperLog {
    pub sequence: u64,
    pub vpn_type: VpnType,
    pub text: String,
}

/** helper 对单条命令的统一响应。 */
#[derive(Debug, Serialize, Deserialize)]
pub struct HelperResponse {
    pub success: bool,
    pub error: Option<String>,
    pub snapshot: HelperSnapshot,
    pub logs: Vec<HelperLog>,
}

impl HelperResponse {
    /** 创建成功响应。 */
    pub fn success(snapshot: HelperSnapshot, logs: Vec<HelperLog>) -> Self {
        Self {
            success: true,
            error: None,
            snapshot,
            logs,
        }
    }

    /** 创建不泄露敏感配置的失败响应。 */
    pub fn failure(error: impl Into<String>, snapshot: HelperSnapshot) -> Self {
        Self {
            success: false,
            error: Some(error.into()),
            snapshot,
            logs: Vec::new(),
        }
    }
}
