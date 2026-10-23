use crate::error::AppResult;
use crate::models::NetworkConnection;
use crate::platform::{self, PlatformAudit};

pub fn connections(adapter: &dyn PlatformAudit) -> AppResult<Vec<NetworkConnection>> {
    adapter.connections()
}

pub fn default_connections() -> AppResult<Vec<NetworkConnection>> {
    let adapter = platform::adapter();
    connections(adapter.as_ref())
}
