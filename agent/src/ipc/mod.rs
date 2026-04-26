use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::db::Database;
use crate::quarantine::QuarantineManager;

// ─── JSON-RPC 2.0 types ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Option<Value>,
    id: Option<Value>,
    auth: String,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
    id: Option<Value>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

impl JsonRpcResponse {
    fn ok(id: Option<Value>, result: Value) -> Self {
        Self { jsonrpc: "2.0".into(), result: Some(result), error: None, id }
    }

    fn err(id: Option<Value>, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: None,
            error: Some(JsonRpcError { code, message: message.into() }),
            id,
        }
    }
}

// ─── IPC Server ───────────────────────────────────────────────────────────────

pub struct IpcServer {
    config: Config,
    db: Arc<Database>,
    auth_token: String,
    shutdown_rx: broadcast::Receiver<()>,
}

impl IpcServer {
    pub fn new(
        config: Config,
        db: Arc<Database>,
        auth_token: String,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Self {
        Self { config, db, auth_token, shutdown_rx }
    }

    pub async fn run(mut self) -> Result<()> {
        let pipe_name = self.config.ipc.pipe_name.clone();
        info!("IPC server starting on {}", pipe_name);

        loop {
            // Check for shutdown before accepting
            if self.shutdown_rx.try_recv().is_ok() {
                info!("IPC server shutting down");
                break;
            }

            // Accept connection on named pipe (blocking, run in spawn_blocking)
            let pipe_name_clone = pipe_name.clone();
            let token = self.auth_token.clone();
            let db = Arc::clone(&self.db);
            let config = self.config.clone();

            let accept_result = tokio::task::spawn_blocking(move || {
                accept_and_handle(pipe_name_clone, token, db, config)
            });

            tokio::select! {
                _ = self.shutdown_rx.recv() => {
                    info!("IPC server shutting down");
                    break;
                }
                result = accept_result => {
                    if let Err(e) = result {
                        error!("IPC handler task error: {:?}", e);
                    }
                }
            }
        }

        Ok(())
    }
}

fn accept_and_handle(
    pipe_name: String,
    auth_token: String,
    db: Arc<Database>,
    config: Config,
) -> Result<()> {
    use std::fs::OpenOptions;

    // Create named pipe server
    // On Windows, use CreateNamedPipeW via the `windows` crate or fall back to
    // opening an existing pipe. For simplicity in MVP, we create the pipe via
    // a named pipe server handle.
    let pipe = create_named_pipe_server(&pipe_name)?;

    // Wait for client connection (ConnectNamedPipe)
    connect_named_pipe(&pipe)?;

    // Handle the request
    let mut reader = BufReader::new(&pipe);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let line = line.trim();

    if line.is_empty() {
        return Ok(());
    }

    let response = match serde_json::from_str::<JsonRpcRequest>(line) {
        Err(_) => JsonRpcResponse::err(None, -32700, "Parse error"),
        Ok(req) => {
            if req.auth != auth_token {
                warn!("IPC: unauthorized request for method '{}'", req.method);
                JsonRpcResponse::err(req.id, -32001, "Unauthorized")
            } else {
                let id = req.id.clone();
                match dispatch(&req.method, req.params, &db, &config) {
                    Ok(result) => JsonRpcResponse::ok(id, result),
                    Err(e) => JsonRpcResponse::err(id, -32603, e.to_string()),
                }
            }
        }
    };

    let mut resp_bytes = serde_json::to_vec(&response)?;
    resp_bytes.push(b'\n');
    (&pipe).write_all(&resp_bytes)?;
    (&pipe).flush()?;

    Ok(())
}

// ─── Named Pipe helpers (Windows) ────────────────────────────────────────────

fn create_named_pipe_server(name: &str) -> Result<std::fs::File> {
    use std::os::windows::io::FromRawHandle;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::*;
    use windows::Win32::System::Pipes::*;
    use windows::Win32::Foundation::INVALID_HANDLE_VALUE;

    let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(name_wide.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            65536,
            65536,
            0,
            None,
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return Err(anyhow::anyhow!(
            "CreateNamedPipeW failed: {:?}",
            windows::Win32::Foundation::GetLastError()
        ));
    }

    Ok(unsafe { std::fs::File::from_raw_handle(handle.0 as *mut _) })
}

fn connect_named_pipe(pipe: &std::fs::File) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::System::Pipes::ConnectNamedPipe;
    use windows::Win32::Foundation::HANDLE;

    let handle = HANDLE(pipe.as_raw_handle() as isize);
    unsafe { ConnectNamedPipe(handle, None)? };
    Ok(())
}

// ─── Method dispatch ─────────────────────────────────────────────────────────

fn dispatch(method: &str, params: Option<Value>, db: &Database, config: &Config) -> Result<Value> {
    match method {
        "get_status" => get_status(db, config),
        "get_stats" => get_stats(db),
        "get_threats" => get_threats(db, params),
        "get_events" => get_events(db, params),
        "get_quarantine" => get_quarantine(db),
        "get_feed_status" => get_feed_status(db),
        "get_config" => Ok(serde_json::to_value(config)?),
        "get_processes" => get_processes(db),
        "get_connections" => get_connections(db),
        "kill_process" => kill_process(params),
        "quarantine_file" => quarantine_file(params, db, config),
        "restore_quarantine" => restore_quarantine(params, db, config),
        "delete_quarantine" => delete_quarantine(params, db, config),
        "pause_protection" => pause_protection(db),
        "resume_protection" => resume_protection(db),
        "update_feeds" => Ok(json!({"queued": true})),
        "add_exception" => add_exception(params, db),
        "block_ioc" => block_ioc(params, db),
        _ => Err(anyhow::anyhow!("Method not found: {}", method)),
    }
}

fn get_status(db: &Database, config: &Config) -> Result<Value> {
    let protection_paused = db
        .get_config_value("protection_paused")
        .unwrap_or_default()
        .map(|v| v == "true")
        .unwrap_or(false);

    Ok(json!({
        "running": true,
        "protection_enabled": !protection_paused,
        "version": env!("CARGO_PKG_VERSION"),
        "last_update": db.get_last_feed_update().unwrap_or_default(),
        "uptime_seconds": get_uptime_seconds(),
    }))
}

fn get_stats(db: &Database) -> Result<Value> {
    let stats = db.get_stats()?;
    Ok(serde_json::to_value(stats)?)
}

fn get_threats(db: &Database, params: Option<Value>) -> Result<Value> {
    let limit = params.as_ref()
        .and_then(|p| p.get("limit"))
        .and_then(|v| v.as_i64())
        .unwrap_or(100);
    let offset = params.as_ref()
        .and_then(|p| p.get("offset"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let threats = db.query_threats(limit, offset)?;
    Ok(serde_json::to_value(threats)?)
}

fn get_events(db: &Database, params: Option<Value>) -> Result<Value> {
    let limit = params.as_ref()
        .and_then(|p| p.get("limit"))
        .and_then(|v| v.as_i64())
        .unwrap_or(200);
    let offset = params.as_ref()
        .and_then(|p| p.get("offset"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let events = db.query_events(limit, offset)?;
    Ok(serde_json::to_value(events)?)
}

fn get_quarantine(db: &Database) -> Result<Value> {
    let entries = db.query_quarantine()?;
    Ok(serde_json::to_value(entries)?)
}

fn get_feed_status(db: &Database) -> Result<Value> {
    let statuses = db.get_all_feed_statuses()?;
    Ok(serde_json::to_value(statuses)?)
}

fn get_processes(db: &Database) -> Result<Value> {
    let procs = db.get_latest_process_snapshot()?;
    Ok(serde_json::to_value(procs)?)
}

fn get_connections(db: &Database) -> Result<Value> {
    let conns = db.get_latest_connections(50)?;
    Ok(serde_json::to_value(conns)?)
}

fn kill_process(params: Option<Value>) -> Result<Value> {
    let pid = params
        .as_ref()
        .and_then(|p| p.get("pid"))
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("pid required"))? as u32;

    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, false, pid)?;
        TerminateProcess(handle, 1)?;
        CloseHandle(handle)?;
    }

    info!("Killed process PID={}", pid);
    Ok(json!({"killed": pid}))
}

fn quarantine_file(params: Option<Value>, db: &Database, config: &Config) -> Result<Value> {
    let path = params
        .as_ref()
        .and_then(|p| p.get("path"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("path required"))?;

    let mgr = QuarantineManager::new(config.quarantine.quarantine_dir.clone(), db);
    let id = mgr.quarantine_file(std::path::Path::new(path), None, None)?;
    Ok(json!({"quarantined": id}))
}

fn restore_quarantine(params: Option<Value>, db: &Database, config: &Config) -> Result<Value> {
    let id = params
        .as_ref()
        .and_then(|p| p.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("id required"))?;

    let mgr = QuarantineManager::new(config.quarantine.quarantine_dir.clone(), db);
    mgr.restore_file(id)?;
    Ok(json!({"restored": id}))
}

fn delete_quarantine(params: Option<Value>, db: &Database, config: &Config) -> Result<Value> {
    let id = params
        .as_ref()
        .and_then(|p| p.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("id required"))?;

    let mgr = QuarantineManager::new(config.quarantine.quarantine_dir.clone(), db);
    mgr.delete_file(id)?;
    Ok(json!({"deleted": id}))
}

fn pause_protection(db: &Database) -> Result<Value> {
    db.set_config_value("protection_paused", "true")?;
    Ok(json!({"paused": true}))
}

fn resume_protection(db: &Database) -> Result<Value> {
    db.set_config_value("protection_paused", "false")?;
    Ok(json!({"paused": false}))
}

fn add_exception(params: Option<Value>, db: &Database) -> Result<Value> {
    let path = params
        .as_ref()
        .and_then(|p| p.get("path"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("path required"))?;

    db.set_config_value(&format!("exception:{}", path), "true")?;
    Ok(json!({"added": path}))
}

fn block_ioc(params: Option<Value>, db: &Database) -> Result<Value> {
    let ioc_type = params.as_ref()
        .and_then(|p| p.get("ioc_type"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("ioc_type required"))?;
    let value = params.as_ref()
        .and_then(|p| p.get("value"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("value required"))?;

    use crate::db::IocEntry;
    use chrono::Utc;
    db.upsert_ioc(&IocEntry {
        id: None,
        ioc_type: ioc_type.to_string(),
        value: value.to_string(),
        source: "manual_block".to_string(),
        confidence: 100,
        first_seen: Some(Utc::now().to_rfc3339()),
        last_seen: Some(Utc::now().to_rfc3339()),
        tags: Some("[\"manual\"]".to_string()),
        is_allowlist: false,
    })?;
    Ok(json!({"blocked": {"type": ioc_type, "value": value}}))
}

fn get_uptime_seconds() -> u64 {
    use windows::Win32::System::SystemInformation::GetTickCount64;
    unsafe { GetTickCount64() / 1000 }
}
