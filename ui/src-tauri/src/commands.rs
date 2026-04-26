use std::sync::Arc;
use serde_json::Value;
use tauri::State;
use tokio::sync::Mutex;

use crate::ipc_client::IpcClient;

pub type IpcState = Arc<Mutex<IpcClient>>;

#[tauri::command]
pub async fn ipc_call(
    state: State<'_, IpcState>,
    method: String,
    params: Option<Value>,
) -> Result<Value, String> {
    let client = state.lock().await;
    client.call(&method, params).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn open_file_dialog(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let file = app.dialog().file().blocking_pick_file();
    Ok(file.and_then(|f| f.into_path().ok()).map(|p| p.to_string_lossy().into_owned()))
}

#[tauri::command]
pub async fn open_folder_dialog(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let folder = app.dialog().file().blocking_pick_folder();
    Ok(folder.and_then(|f| f.into_path().ok()).map(|p| p.to_string_lossy().into_owned()))
}
