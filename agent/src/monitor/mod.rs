pub mod file_monitor;
pub mod network_monitor;
pub mod process_monitor;
pub mod registry_monitor;

/// Events emitted by monitors and consumed by the IPC layer / event log.
#[derive(Debug, Clone)]
pub enum MonitorEvent {
    FileThreat {
        path: String,
        score: u8,
        method: String,
    },
    ProcessAlert {
        pid: u32,
        name: String,
        path: String,
        score: u8,
        flags: Vec<String>,
    },
    NetworkAlert {
        pid: u32,
        remote_addr: String,
        remote_port: u16,
        score: u8,
    },
    RegistryAlert {
        key: String,
        value_name: String,
        details: String,
    },
    RansomwareAlert {
        path: String,
        files_modified: u32,
    },
}
