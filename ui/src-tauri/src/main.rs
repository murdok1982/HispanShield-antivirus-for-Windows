#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod ipc_client;

use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("HispanShield UI starting");

    let token = load_ipc_token();
    let ipc = ipc_client::IpcClient::new(r"\\.\pipe\HispanShieldAgent", &token);
    let ipc_state = Arc::new(Mutex::new(ipc));

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(ipc_state)
        .invoke_handler(tauri::generate_handler![
            commands::ipc_call,
            commands::open_file_dialog,
            commands::open_folder_dialog,
        ])
        .run(tauri::generate_context!())
        .expect("error while running HispanShield UI");
}

fn load_ipc_token() -> String {
    let path = std::path::Path::new("C:\\ProgramData\\HispanShield\\ipc_token");
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .trim()
        .to_string()
}
