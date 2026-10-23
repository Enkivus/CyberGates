use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use crate::db::Db;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub data_dir: PathBuf,
    pub reports_dir: PathBuf,
    pub log_dir: PathBuf,
    pub audit_running: Arc<AtomicBool>,
    pub advisory_update_running: Arc<AtomicBool>,
}

impl AppState {
    pub fn new(db: Db, data_dir: PathBuf, log_dir: PathBuf) -> Self {
        let reports_dir = data_dir.join("reports");
        Self {
            db,
            data_dir,
            reports_dir,
            log_dir,
            audit_running: Arc::new(AtomicBool::new(false)),
            advisory_update_running: Arc::new(AtomicBool::new(false)),
        }
    }
}
