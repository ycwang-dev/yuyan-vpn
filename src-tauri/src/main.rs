#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(target_os = "windows")]
    if yuyan_app_lib::run_windows_vpn_helper_if_requested() {
        return;
    }
    yuyan_app_lib::run();
}
