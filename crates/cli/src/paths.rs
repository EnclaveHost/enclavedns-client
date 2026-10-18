//! Where things live on each platform.

use std::path::PathBuf;

#[cfg(windows)]
pub fn program_data() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("EnclaveDNS")
}

pub fn config_file() -> PathBuf {
    #[cfg(windows)]
    return program_data().join("config.toml");
    #[cfg(not(windows))]
    return PathBuf::from("/etc/enclavedns/config.toml");
}

/// The client's own state (the .eth CA). systemd names it in STATE_DIRECTORY.
pub fn state_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("STATE_DIRECTORY") {
        return PathBuf::from(d);
    }
    #[cfg(windows)]
    return program_data().join("state");
    #[cfg(not(windows))]
    return PathBuf::from("/var/lib/enclavedns");
}
