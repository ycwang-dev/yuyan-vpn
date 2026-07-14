use std::fs::File;
use std::path::Path;

fn main() {
    // 自动在 target 目录下创建 .metadata_never_index 阻止 macOS 索引开发构建产物，避免 Launchpad 出现重复 App 图标
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let target_dir = Path::new(&manifest_dir).join("target");
        if target_dir.exists() {
            let never_index_path = target_dir.join(".metadata_never_index");
            if !never_index_path.exists() {
                let _ = File::create(never_index_path);
            }
        }
    }

    tauri_build::build()
}
