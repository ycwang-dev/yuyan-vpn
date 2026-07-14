use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};

/** 允许注入 Rust 后端和 Vite 前端共用的 VPN 构建参数。 */
const VPN_BUILD_KEYS: [&str; 7] = [
    "VITE_DEFAULT_FORTINET_HOST",
    "VITE_DEFAULT_FORTINET_PORT",
    "VITE_DEFAULT_FORTINET_USERNAME",
    "VITE_DEFAULT_FORTINET_ROUTES",
    "VITE_DEFAULT_ATRUST_HOST",
    "VITE_DEFAULT_ATRUST_PORT",
    "VITE_DEFAULT_ATRUST_USERNAME",
];

/** 解析本地 `.env.local`，仅提取允许进入安装包的 VPN 构建参数。 */
fn read_local_vpn_env(path: &Path) -> HashMap<String, String> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return HashMap::new();
    };

    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, raw_value) = line.split_once('=')?;
            let key = key.trim().trim_start_matches("export ");
            if !VPN_BUILD_KEYS.contains(&key) {
                return None;
            }

            let value = raw_value.trim();
            let value = if value.len() >= 2
                && ((value.starts_with('"') && value.ends_with('"'))
                    || (value.starts_with('\'') && value.ends_with('\'')))
            {
                &value[1..value.len() - 1]
            } else {
                value
            };
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

/**
 * 将 CI 环境变量或本机 `.env.local` 中的 VPN 参数传给 Rust 编译器。
 *
 * CI 环境变量优先；真实值不会写入公开源码，缺失时由运行时占位配置门禁阻止误连接。
 */
fn expose_vpn_build_configuration(manifest_dir: &Path) {
    let local_env_path: PathBuf = manifest_dir.join("..").join(".env.local");
    println!("cargo:rerun-if-changed={}", local_env_path.display());
    let local_values = read_local_vpn_env(&local_env_path);

    for key in VPN_BUILD_KEYS {
        println!("cargo:rerun-if-env-changed={key}");
        let value = std::env::var(key)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| local_values.get(key).cloned());
        if let Some(value) =
            value.filter(|value| !value.chars().any(|char| matches!(char, '\r' | '\n')))
        {
            println!("cargo:rustc-env={key}={value}");
        }
    }
}

fn main() {
    // 自动在 target 目录下创建 .metadata_never_index 阻止 macOS 索引开发构建产物，避免 Launchpad 出现重复 App 图标
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let manifest_dir = Path::new(&manifest_dir);
        expose_vpn_build_configuration(manifest_dir);
        let target_dir = manifest_dir.join("target");
        if target_dir.exists() {
            let never_index_path = target_dir.join(".metadata_never_index");
            if !never_index_path.exists() {
                let _ = File::create(never_index_path);
            }
        }
    }

    tauri_build::build()
}
