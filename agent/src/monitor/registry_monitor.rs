use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::config::Config;
use crate::db::Database;

const AUTORUN_KEYS: &[&str] = &[
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"SYSTEM\CurrentControlSet\Services",
];

pub async fn run(
    config: Config,
    db: Arc<Database>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> Result<()> {
    info!("Registry monitor started");
    let interval = Duration::from_secs(30);

    // Snapshot current autorun values
    let mut baseline = snapshot_autorun_keys();

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("Registry monitor stopping");
                break;
            }
            _ = tokio::time::sleep(interval) => {
                let current = snapshot_autorun_keys();

                for (key, values) in &current {
                    let baseline_vals = baseline.get(key).cloned().unwrap_or_default();

                    for (val_name, val_data) in values {
                        if !baseline_vals.contains(&(val_name.clone(), val_data.clone())) {
                            warn!(
                                "New/modified autorun entry: {}\\{} = {}",
                                key, val_name, val_data
                            );

                            // Log event
                            let _ = db.insert_event(&crate::db::Event {
                                id: None,
                                timestamp: Utc::now().to_rfc3339(),
                                event_type: "RegistryChange".to_string(),
                                severity: "High".to_string(),
                                source: Some("RegistryMonitor".to_string()),
                                path: Some(format!("{}\\{}", key, val_name)),
                                pid: None,
                                process_name: None,
                                score: Some(35),
                                details: Some(format!(
                                    r#"{{"key":"{}","value_name":"{}","data":"{}"}}"#,
                                    key, val_name, val_data
                                )),
                                resolved: false,
                            });
                        }
                    }
                }

                baseline = current;
            }
        }
    }

    Ok(())
}

type AutorunSnapshot = std::collections::HashMap<String, Vec<(String, String)>>;

fn snapshot_autorun_keys() -> AutorunSnapshot {
    let mut result = AutorunSnapshot::new();

    for key_path in AUTORUN_KEYS {
        let values = read_registry_key_values(key_path);
        if !values.is_empty() {
            result.insert(key_path.to_string(), values);
        }
    }

    result
}

fn read_registry_key_values(key_path: &str) -> Vec<(String, String)> {
    use windows::Win32::System::Registry::*;
    use windows::core::PCWSTR;

    let mut values = Vec::new();

    // Try HKLM first
    for hive in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
        let path_wide: Vec<u16> = key_path.encode_utf16().chain(std::iter::once(0)).collect();
        let mut hkey = HKEY::default();

        let result = unsafe {
            RegOpenKeyExW(hive, PCWSTR(path_wide.as_ptr()), 0, KEY_READ, &mut hkey)
        };

        if result.is_err() {
            continue;
        }

        let mut index = 0u32;
        loop {
            let mut name_buf = [0u16; 256];
            let mut name_len = 256u32;
            let mut data_buf = [0u8; 1024];
            let mut data_len = 1024u32;
            let mut val_type = 0u32;

            let r = unsafe {
                RegEnumValueW(
                    hkey,
                    index,
                    windows::core::PWSTR(name_buf.as_mut_ptr()),
                    &mut name_len,
                    None,
                    Some(&mut val_type),
                    Some(data_buf.as_mut_ptr()),
                    Some(&mut data_len),
                )
            };

            if r.is_err() {
                break;
            }

            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            let data = if val_type == 1 || val_type == 2 {
                // REG_SZ or REG_EXPAND_SZ
                let chars: Vec<u16> = data_buf[..data_len as usize]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16_lossy(&chars).trim_end_matches('\0').to_string()
            } else {
                format!("<binary:{}>", data_len)
            };

            values.push((name, data));
            index += 1;
        }

        unsafe { RegCloseKey(hkey).ok() };
    }

    values
}
