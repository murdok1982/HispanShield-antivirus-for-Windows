mod config;
mod db;
mod hispan_shield_guardian;
mod detection;
mod firewall;
mod ipc;
mod monitor;
mod quarantine;
mod runtime;
mod scoring;
mod service;
mod threat_intel;

use anyhow::Result;

pub const SERVICE_NAME: &str = "HispanShieldAgent";
pub const SERVICE_DISPLAY: &str = "HispanShield Security Agent";
pub const SERVICE_DESCRIPTION: &str =
    "Real-time protection, threat detection and network monitoring for HispanShield Antivirus";

fn main() -> Result<()> {
    hispan_shield_guardian::hispan_shield_audit();
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("");

    match command {
        "install" => service::install_service()?,
        "uninstall" => service::uninstall_service()?,
        "start" => service::start_service()?,
        "stop" => service::stop_service()?,
        "run" => service::run_service()?,
        _ => {
            // Try running as Windows Service dispatcher first (when launched by SCM)
            service::run_service().unwrap_or_else(|_| {
                eprintln!(
                    "HispanShield Security Agent\n\
                     Usage: hispanshield-agent [install|uninstall|start|stop|run]\n\
                     \n\
                     Commands:\n\
                     \  install    Register the Windows service\n\
                     \  uninstall  Remove the Windows service\n\
                     \  start      Start the service via SCM\n\
                     \  stop       Stop the service via SCM\n\
                     \  run        Run the agent (used by SCM internally)"
                );
            });
        }
    }
    Ok(())
}
