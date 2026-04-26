use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{error, info};
use anyhow::Result;

use crate::config::Config;
use crate::db::Database;
use crate::ipc::IpcServer;
use crate::monitor::{file_monitor, network_monitor, process_monitor, registry_monitor};
use crate::threat_intel::FeedManager;

/// Main async runtime: loads config, opens DB, spawns all monitor/service tasks.
pub async fn run(mut shutdown_rx: broadcast::Receiver<()>) -> Result<()> {
    let config = Config::load().unwrap_or_default();
    info!("Config loaded from {}", config.general.data_dir.display());

    // Ensure data directories exist
    std::fs::create_dir_all(&config.general.data_dir)?;
    std::fs::create_dir_all(&config.general.log_dir)?;
    std::fs::create_dir_all(&config.quarantine.quarantine_dir)?;

    // Open database
    let db = Database::open(&config.general.db_path)?;
    let db = Arc::new(db);

    // Load IPC auth token
    let token = std::fs::read_to_string(&config.ipc.auth_token_path)
        .unwrap_or_default()
        .trim()
        .to_string();

    // ── Launch all background tasks ──────────────────────────────────────────

    let (event_tx, _) = tokio::sync::broadcast::channel(512);

    // File monitor
    let fm_db = Arc::clone(&db);
    let fm_cfg = config.clone();
    let fm_tx = event_tx.clone();
    let fm_shutdown = shutdown_rx.resubscribe();
    let file_task = tokio::spawn(async move {
        if let Err(e) = file_monitor::run(fm_cfg, fm_db, fm_tx, fm_shutdown).await {
            error!("File monitor error: {:?}", e);
        }
    });

    // Process monitor
    let pm_db = Arc::clone(&db);
    let pm_cfg = config.clone();
    let pm_tx = event_tx.clone();
    let pm_shutdown = shutdown_rx.resubscribe();
    let process_task = tokio::spawn(async move {
        if let Err(e) = process_monitor::run(pm_cfg, pm_db, pm_tx, pm_shutdown).await {
            error!("Process monitor error: {:?}", e);
        }
    });

    // Network monitor
    let nm_db = Arc::clone(&db);
    let nm_cfg = config.clone();
    let nm_tx = event_tx.clone();
    let nm_shutdown = shutdown_rx.resubscribe();
    let network_task = tokio::spawn(async move {
        if let Err(e) = network_monitor::run(nm_cfg, nm_db, nm_tx, nm_shutdown).await {
            error!("Network monitor error: {:?}", e);
        }
    });

    // Registry monitor
    let rm_db = Arc::clone(&db);
    let rm_cfg = config.clone();
    let rm_shutdown = shutdown_rx.resubscribe();
    let registry_task = tokio::spawn(async move {
        if let Err(e) = registry_monitor::run(rm_cfg, rm_db, rm_shutdown).await {
            error!("Registry monitor error: {:?}", e);
        }
    });

    // Threat intelligence feed updater
    let ti_db = Arc::clone(&db);
    let ti_cfg = config.clone();
    let ti_shutdown = shutdown_rx.resubscribe();
    let intel_task = tokio::spawn(async move {
        if let Err(e) = FeedManager::run_scheduled(ti_cfg, ti_db, ti_shutdown).await {
            error!("Feed manager error: {:?}", e);
        }
    });

    // IPC server (last — depends on DB being ready)
    let ipc_db = Arc::clone(&db);
    let ipc_cfg = config.clone();
    let ipc_shutdown = shutdown_rx.resubscribe();
    let ipc_task = tokio::spawn(async move {
        let server = IpcServer::new(ipc_cfg, ipc_db, token, ipc_shutdown);
        if let Err(e) = server.run().await {
            error!("IPC server error: {:?}", e);
        }
    });

    info!("All modules started. Waiting for shutdown signal...");

    // Wait for shutdown
    let _ = shutdown_rx.recv().await;
    info!("Shutdown signal received, stopping tasks...");

    // Abort all tasks gracefully
    file_task.abort();
    process_task.abort();
    network_task.abort();
    registry_task.abort();
    intel_task.abort();
    ipc_task.abort();

    info!("All tasks stopped.");
    Ok(())
}
