//! The EnclaveDNS client, shared by the Linux and Windows daemon and the
//! Android app.
//!
//! * A DNS stub resolver: every question goes to EnclaveDNS (a validating
//!   DNSSEC resolver in an attested enclave) over DoH, through a cache; a
//!   fallback resolver only while EnclaveDNS cannot be reached.
//! * `.eth` sites in an ordinary browser: names that hold content get the
//!   gateway address, and the gateway serves the site from the LOCAL IPFS,
//!   Swarm, Arweave or Tor software, over HTTPS from a CA that exists only
//!   on this device and can only vouch for `.eth`/`.ens` names. When the
//!   software is missing, a page says which and how to start it.

pub mod cache;
pub mod config;
pub mod dns;
pub mod ens;
pub mod gateway;
pub mod pages;
pub mod tls;
pub mod upstream;

pub use config::Config;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Default, Clone, Debug, serde::Serialize)]
pub struct Counters {
    pub cached: u64,
    pub enclavedns: u64,
    pub fallback: u64,
    pub failed: u64,
    pub forwarded: u64,
}

pub struct Engine {
    pub cfg: Config,
    pub up: upstream::Upstream,
    pub cache: cache::Cache,
    pub ens: ens::Ens,
    pub backends: gateway::Backends,
    /// None when HTTPS is off
    pub tls: Option<Arc<rustls::ServerConfig>>,
    pub state_dir: PathBuf,
    pub counters: Mutex<Counters>,
    started: Instant,
}

impl Engine {
    /// `state_dir` holds the .eth CA (made there on first start).
    pub fn new(cfg: Config, state_dir: &Path) -> Result<Arc<Engine>, String> {
        cfg.check()?;
        let boot = upstream::Bootstrap::new(cfg.bootstrap.clone());
        let up = upstream::Upstream::new(&cfg, boot);
        let ens = ens::Ens::new(&cfg.ens_base(), up.http().clone());
        let tls = if cfg.https {
            let ca = tls::Ca::load_or_create(state_dir).map_err(|e| format!("the .eth CA: {e}"))?;
            Some(Arc::new(ca).server_config())
        } else {
            None
        };
        Ok(Arc::new(Engine {
            cache: cache::Cache::new(cfg.cache_entries),
            backends: gateway::Backends::default(),
            ens,
            up,
            tls,
            state_dir: state_dir.to_path_buf(),
            counters: Mutex::default(),
            started: Instant::now(),
            cfg,
        }))
    }

    /// The CA certificate users trust for HTTPS on `.eth`.
    pub fn ca_cert_path(&self) -> PathBuf {
        self.state_dir.join(tls::CA_CERT)
    }

    /// The answer to one DNS message (UDP-sized), or None to drop it.
    pub async fn answer_udp(&self, wire: &[u8]) -> Option<Vec<u8>> {
        dns::answer_udp(self, wire).await
    }

    pub async fn status(&self) -> serde_json::Value {
        let mut b = serde_json::Map::new();
        for k in gateway::Kind::ALL {
            b.insert(
                k.label().to_ascii_lowercase(),
                serde_json::json!({"at": gateway::backend_url(self, k), "detected": self.backends.up(self, k).await}),
            );
        }
        let up = self.up.stats.lock().unwrap().clone();
        serde_json::json!({
            "service": "enclavedns-client",
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_s": self.started.elapsed().as_secs(),
            "upstream": self.cfg.upstream,
            "upstream_reachable": !self.up.primary_down(),
            "upstream_stats": up,
            "fallback": self.cfg.fallback,
            "forward": self.cfg.forward,
            "queries": *self.counters.lock().unwrap(),
            "cache_entries": self.cache.len(),
            "gateway": self.cfg.gateway.to_string(),
            "https": self.tls.is_some(),
            "ca_cert": self.ca_cert_path().display().to_string(),
            "backends": b,
        })
    }

    /// Bind everything the config names and serve until the process ends
    /// (Linux and Windows; Android feeds the engine from its VPN instead).
    pub async fn run(self: Arc<Self>) -> Result<(), String> {
        let mut tasks = tokio::task::JoinSet::new();
        let mut bound = Vec::new();
        for a in &self.cfg.dns_listen {
            match (
                tokio::net::UdpSocket::bind(a).await,
                tokio::net::TcpListener::bind(a).await,
            ) {
                (Ok(u), Ok(t)) => {
                    tasks.spawn(dns::serve_udp(u, self.clone()));
                    tasks.spawn(dns::serve_tcp(t, self.clone()));
                    bound.push(format!("dns {a}"));
                }
                (u, t) => {
                    let e = u
                        .err()
                        .or(t.err())
                        .map(|e| e.to_string())
                        .unwrap_or_default();
                    // IPv6 loopback may be disabled; IPv4 must work
                    if a.is_ipv4() {
                        return Err(format!("cannot listen for DNS on {a}: {e}"));
                    }
                    eprintln!("enclavedns: skipping {a}: {e}");
                }
            }
        }
        let gw = self.cfg.gateway;
        let http = tokio::net::TcpListener::bind((gw, self.cfg.http_port))
            .await
            .map_err(|e| format!("cannot listen on {gw}:{}: {e}", self.cfg.http_port))?;
        tasks.spawn(gateway::serve(http, self.clone(), None));
        bound.push(format!("http {gw}:{}", self.cfg.http_port));
        if let Some(t) = &self.tls {
            let https = tokio::net::TcpListener::bind((gw, self.cfg.https_port))
                .await
                .map_err(|e| format!("cannot listen on {gw}:{}: {e}", self.cfg.https_port))?;
            tasks.spawn(gateway::serve(
                https,
                self.clone(),
                Some(tokio_rustls::TlsAcceptor::from(t.clone())),
            ));
            bound.push(format!("https {gw}:{}", self.cfg.https_port));
        }
        eprintln!(
            "enclavedns {}: {}; upstream {}",
            env!("CARGO_PKG_VERSION"),
            bound.join(", "),
            self.cfg.upstream
        );
        while tasks.join_next().await.is_some() {}
        Ok(())
    }
}
