//! Configuration: one TOML file, every field optional.
//!
//! ```toml
//! upstream = "https://59f1273d.app.enclave.host"   # EnclaveDNS
//! fallback = ["https://dns.quad9.net/dns-query"]   # [] = no fallback
//! bootstrap = ["9.9.9.9:53", "1.1.1.1:53"]
//! dns_listen = ["127.0.0.1:53", "[::1]:53"]
//! gateway = "127.0.0.3"
//! https = true
//! redirect_https = true
//!
//! [backends]
//! ipfs = "http://127.0.0.1:8080"
//! ipfs_api = "http://127.0.0.1:5001"
//! bee = "http://127.0.0.1:1633"
//! arweave = "http://127.0.0.1:3000"
//! tor = ["127.0.0.1:9050", "127.0.0.1:9150"]
//! ```

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// EnclaveDNS: DoH at `<upstream>/dns-query`, ENS at `<upstream>/api/ens/<name>`
    pub upstream: String,
    /// DoH resolvers used only while EnclaveDNS cannot be reached. A DNS
    /// answer from EnclaveDNS, SERVFAIL included (a DNSSEC failure), is never
    /// retried here.
    pub fallback: Vec<String>,
    /// Plain DNS servers that find the upstreams' own addresses (the system
    /// resolver points at this client, so it cannot be asked).
    pub bootstrap: Vec<SocketAddr>,
    /// Where the stub resolver listens. Empty on Android (the VPN carries DNS).
    pub dns_listen: Vec<SocketAddr>,
    /// The address `.eth` names get when this client serves their sites.
    pub gateway: IpAddr,
    pub http_port: u16,
    pub https_port: u16,
    /// serve `.eth` sites over HTTPS from the local, .eth-only CA
    pub https: bool,
    /// send http:// `.eth` requests to https:// (the CA must be trusted)
    pub redirect_https: bool,
    /// where the CA lives; the platform's state directory when unset
    pub state_dir: Option<PathBuf>,
    /// answers kept in memory
    pub cache_entries: usize,
    /// Names only the local network knows (`*.lan`, a router's own zone):
    /// asked of these servers with plain DNS, never of EnclaveDNS.
    /// `enclavedns enable` fills this from the network's search domains.
    pub forward: Vec<ForwardZone>,
    pub backends: Backends,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ForwardZone {
    pub zone: String,
    pub servers: Vec<SocketAddr>,
}

impl ForwardZone {
    /// Does `name` (lowercase, trailing dot) fall inside this zone?
    pub fn covers(&self, name: &str) -> bool {
        let z = format!("{}.", self.zone.trim_matches('.').to_ascii_lowercase());
        name == z || name.ends_with(&format!(".{z}"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Backends {
    /// kubo's gateway (IPFS and IPNS sites)
    pub ipfs: String,
    /// kubo's RPC API, used only to resolve IPNS names quickly
    pub ipfs_api: String,
    /// a Bee node's API (Swarm sites)
    pub bee: String,
    /// an AR.IO gateway (Arweave sites)
    pub arweave: String,
    /// Tor SOCKS ports, tried in order (tor: 9050, Tor Browser: 9150)
    pub tor: Vec<SocketAddr>,
}

impl Default for Backends {
    fn default() -> Self {
        Backends {
            ipfs: "http://127.0.0.1:8080".into(),
            ipfs_api: "http://127.0.0.1:5001".into(),
            bee: "http://127.0.0.1:1633".into(),
            arweave: "http://127.0.0.1:3000".into(),
            tor: vec![
                "127.0.0.1:9050".parse().unwrap(),
                "127.0.0.1:9150".parse().unwrap(),
            ],
        }
    }
}

pub const DEFAULT_UPSTREAM: &str = "https://59f1273d.app.enclave.host";

impl Default for Config {
    fn default() -> Self {
        Config {
            upstream: DEFAULT_UPSTREAM.into(),
            fallback: vec!["https://dns.quad9.net/dns-query".into()],
            bootstrap: vec![
                "9.9.9.9:53".parse().unwrap(),
                "149.112.112.112:53".parse().unwrap(),
                "1.1.1.1:53".parse().unwrap(),
            ],
            dns_listen: vec!["127.0.0.1:53".parse().unwrap(), "[::1]:53".parse().unwrap()],
            gateway: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
            http_port: 80,
            https_port: 443,
            https: true,
            redirect_https: true,
            state_dir: None,
            cache_entries: 20_000,
            forward: Vec::new(),
            backends: Backends::default(),
        }
    }
}

impl Config {
    pub fn from_toml(text: &str) -> Result<Config, String> {
        let c: Config = toml::from_str(text).map_err(|e| e.to_string())?;
        c.check()?;
        Ok(c)
    }

    pub fn load(path: &std::path::Path) -> Result<Config, String> {
        match std::fs::read_to_string(path) {
            Ok(t) => Config::from_toml(&t).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    pub fn check(&self) -> Result<(), String> {
        for u in std::iter::once(&self.upstream).chain(&self.fallback) {
            if !u.starts_with("https://") {
                return Err(format!("{u}: upstreams must be https:// URLs"));
            }
        }
        for f in &self.forward {
            if f.zone.trim_matches('.').is_empty() || f.servers.is_empty() {
                return Err(format!("forward zone {:?} needs a zone name and servers (the root cannot be forwarded)", f.zone));
            }
        }
        if self.bootstrap.is_empty() {
            return Err("bootstrap needs at least one DNS server".into());
        }
        Ok(())
    }

    pub fn upstream_base(&self) -> &str {
        self.upstream.trim_end_matches('/')
    }

    pub fn doh_url(&self) -> String {
        let b = self.upstream_base();
        if b.ends_with("/dns-query") {
            b.to_string()
        } else {
            format!("{b}/dns-query")
        }
    }

    pub fn ens_base(&self) -> String {
        self.upstream_base()
            .trim_end_matches("/dns-query")
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_partial_files() {
        let c = Config::from_toml("").unwrap();
        assert_eq!(c.doh_url(), "https://59f1273d.app.enclave.host/dns-query");
        let c = Config::from_toml("fallback = []\n[backends]\nipfs = \"http://127.0.0.1:8081\"\n")
            .unwrap();
        assert!(c.fallback.is_empty());
        assert_eq!(c.backends.ipfs, "http://127.0.0.1:8081");
        assert_eq!(c.backends.bee, "http://127.0.0.1:1633");
        assert!(Config::from_toml("upstream = \"http://plain\"").is_err());
        assert!(Config::from_toml("nonsense = 1").is_err());
        let c = Config::from_toml("[[forward]]\nzone = \"lan\"\nservers = [\"192.168.8.1:53\"]\n")
            .unwrap();
        assert!(c.forward[0].covers("warden-host.lan."));
        assert!(c.forward[0].covers("lan."));
        assert!(!c.forward[0].covers("plan."));
        assert!(
            Config::from_toml("[[forward]]\nzone = \".\"\nservers = [\"1.1.1.1:53\"]\n").is_err()
        );
    }
}
