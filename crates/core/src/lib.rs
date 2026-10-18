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
pub mod sysdns;
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
    /// answered by this machine's own DNS while EnclaveDNS could not be reached
    pub system: u64,
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
    /// gateway ports that could not be opened, and why
    pub gateway_problems: Mutex<Vec<String>>,
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
            gateway_problems: Mutex::default(),
            started: Instant::now(),
            cfg,
        }))
    }

    /// The CA certificate users trust for HTTPS on `.eth`.
    pub fn ca_cert_path(&self) -> PathBuf {
        self.state_dir.join(tls::CA_CERT)
    }

    fn gateway_problem(&self, p: String) {
        eprintln!("enclavedns: .eth gateway: cannot listen on {p} (DNS is unaffected)");
        self.gateway_problems.lock().unwrap().push(p);
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
            "strict": self.up.strict(),
            "system_dns": self.up.system_dns().iter().map(|a| a.to_string()).collect::<Vec<_>>(),
            "fallback": self.cfg.fallback,
            "forward": self.cfg.forward,
            "queries": *self.counters.lock().unwrap(),
            "cache_entries": self.cache.len(),
            "gateway": self.cfg.gateway.to_string(),
            "gateway_problems": self.gateway_problems.lock().unwrap().clone(),
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
        // The .eth gateway is a convenience; DNS must never go down with it.
        // A port that cannot be bound (on Windows, HTTP.sys often holds :80 on
        // every address) is reported in `status` and the rest carries on.
        // this machine's own DNS, the fallback: found again every minute
        // (networks change), unless the config names it or is strict
        if self.cfg.system_dns.is_empty() && !self.cfg.strict {
            let me = self.clone();
            tasks.spawn(async move {
                loop {
                    if let Ok(found) = tokio::task::spawn_blocking(sysdns::discover).await {
                        me.up.set_system_dns(found);
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                }
            });
        }
        let gw = self.cfg.gateway;
        match tokio::net::TcpListener::bind((gw, self.cfg.http_port)).await {
            Ok(l) => {
                tasks.spawn(gateway::serve(l, self.clone(), None));
                bound.push(format!("http {gw}:{}", self.cfg.http_port));
            }
            Err(e) => self.gateway_problem(format!("http {gw}:{}: {e}", self.cfg.http_port)),
        }
        // status (and the same pages) on a port of its own, for `enclavedns status`
        match tokio::net::TcpListener::bind((gw, self.cfg.status_port)).await {
            Ok(l) => {
                tasks.spawn(gateway::serve(l, self.clone(), None));
                bound.push(format!("status {gw}:{}", self.cfg.status_port));
            }
            Err(e) => self.gateway_problem(format!("status {gw}:{}: {e}", self.cfg.status_port)),
        }
        if let Some(t) = &self.tls {
            match tokio::net::TcpListener::bind((gw, self.cfg.https_port)).await {
                Ok(l) => {
                    tasks.spawn(gateway::serve(
                        l,
                        self.clone(),
                        Some(tokio_rustls::TlsAcceptor::from(t.clone())),
                    ));
                    bound.push(format!("https {gw}:{}", self.cfg.https_port));
                }
                Err(e) => self.gateway_problem(format!("https {gw}:{}: {e}", self.cfg.https_port)),
            }
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
