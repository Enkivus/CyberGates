use sysinfo::{ProcessesToUpdate, System};

use crate::models::{ProcessInfo, SystemInfo};
use crate::platform::PlatformAudit;

pub fn collect(adapter: &dyn PlatformAudit) -> SystemInfo {
    let mut system = System::new_all();
    system.refresh_all();
    let cpu_brand = system
        .cpus()
        .first()
        .map(|cpu| cpu.brand().trim().to_string())
        .filter(|brand| !brand.is_empty())
        .unwrap_or_else(|| "Unknown CPU".to_string());

    SystemInfo {
        hostname: System::host_name().unwrap_or_else(|| "Unknown".to_string()),
        os_name: System::name().unwrap_or_else(|| std::env::consts::OS.to_string()),
        os_version: System::os_version().unwrap_or_else(|| "Unknown".to_string()),
        kernel_version: System::kernel_version().unwrap_or_else(|| "Unknown".to_string()),
        architecture: System::cpu_arch(),
        cpu_brand,
        cpu_cores: system.cpus().len(),
        memory_total_mb: system.total_memory() / (1024 * 1024),
        uptime_seconds: System::uptime(),
        platform: adapter.platform_name().to_string(),
        supported: adapter.supported(),
        notes: adapter.notes(),
    }
}

pub fn processes(limit: usize) -> Vec<ProcessInfo> {
    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::All, true);
    let mut processes: Vec<ProcessInfo> = system
        .processes()
        .iter()
        .map(|(pid, process)| ProcessInfo {
            pid: pid.as_u32(),
            name: process.name().to_string_lossy().to_string(),
            cpu_percent: process.cpu_usage(),
            memory_mb: (process.memory() as f64) / (1024.0 * 1024.0),
            executable: process.exe().map(|path| path.to_string_lossy().to_string()),
            run_time_seconds: process.run_time(),
        })
        .collect();
    processes.sort_by(|a, b| {
        b.cpu_percent
            .partial_cmp(&a.cpu_percent)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.name.cmp(&b.name))
    });
    processes.truncate(limit.clamp(1, 2000));
    processes
}
