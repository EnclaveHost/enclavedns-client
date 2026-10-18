//! Asking upstream: DoH to EnclaveDNS, and to the fallback resolvers only
//! while EnclaveDNS cannot be reached.
//!
//! The system resolver points at this client, so the DoH hosts' own
//! addresses come from a small bootstrap resolver (plain DNS to fixed
//! servers) instead of from the system: asking the system would ask us.

use crate::config::Config;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use reqwest::dns::{Addrs, Resolve, Resolving};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- bootstrap

struct BootInner {
    servers: Vec<SocketAddr>,
    cache: Mutex<HashMap<String, (Instant, Vec<IpAddr>)>>,
}

#[derive(Clone)]
pub struct Bootstrap(Arc<BootInner>);

impl Bootstrap {
    pub fn new(servers: Vec<SocketAddr>) -> Bootstrap {
        Bootstrap(Arc::new(BootInner {
            servers,
            cache: Mutex::default(),
        }))
    }

    pub async fn lookup(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        if let Ok(ip) = IpAddr::from_str(host.trim_matches(['[', ']'])) {
            return Ok(vec![ip]);
        }
        let key = host.to_ascii_lowercase();
        if let Some((until, ips)) = self.0.cache.lock().unwrap().get(&key) {
            if Instant::now() < *until {
                return Ok(ips.clone());
            }
        }
        let mut last = "no bootstrap server answered".to_string();
        for s in &self.0.servers {
            let (a, aaaa) = tokio::join!(
                udp_lookup(*s, &key, RecordType::A),
                udp_lookup(*s, &key, RecordType::AAAA)
            );
            let mut ips = Vec::new();
            let mut ttl = u32::MAX;
            for r in [a, aaaa] {
                match r {
                    Ok((v, t)) => {
                        ips.extend(v);
                        ttl = ttl.min(t);
                    }
                    Err(e) => last = e,
                }
            }
            if !ips.is_empty() {
                // IPv4 first: many networks have broken IPv6
                ips.sort_by_key(|ip| ip.is_ipv6());
                let keep = Duration::from_secs(ttl.clamp(60, 3600) as u64);
                self.0
                    .cache
                    .lock()
                    .unwrap()
                    .insert(key, (Instant::now() + keep, ips.clone()));
                return Ok(ips);
            }
        }
        // the last known address beats none at all
        if let Some((_, ips)) = self.0.cache.lock().unwrap().get(&key) {
            return Ok(ips.clone());
        }
        Err(format!("bootstrap lookup of {host}: {last}"))
    }
}

async fn udp_lookup(
    server: SocketAddr,
    host: &str,
    t: RecordType,
) -> Result<(Vec<IpAddr>, u32), String> {
    let name = Name::from_ascii(format!("{host}.")).map_err(|e| e.to_string())?;
    let mut m = Message::new();
    let id = rand_u16();
    m.set_id(id)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true);
    m.add_query(Query::query(name, t));
    let wire = m.to_vec().map_err(|e| e.to_string())?;
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = tokio::net::UdpSocket::bind(bind)
        .await
        .map_err(|e| e.to_string())?;
    sock.connect(server).await.map_err(|e| e.to_string())?;
    sock.send(&wire).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 2048];
    let fut = async {
        loop {
            let n = sock.recv(&mut buf).await.map_err(|e| e.to_string())?;
            if let Ok(r) = Message::from_vec(&buf[..n]) {
                if r.id() == id {
                    return Ok::<_, String>(r);
                }
            }
        }
    };
    let r = tokio::time::timeout(Duration::from_secs(3), fut)
        .await
        .map_err(|_| format!("{server}: no answer"))??;
    let mut ips = Vec::new();
    let mut ttl = u32::MAX;
    for rec in r.answers() {
        match rec.data() {
            Some(RData::A(a)) => ips.push(IpAddr::V4(a.0)),
            Some(RData::AAAA(a)) => ips.push(IpAddr::V6(a.0)),
            _ => continue,
        }
        ttl = ttl.min(rec.ttl());
    }
    Ok((ips, ttl))
}

/// One DNS message over plain DNS (UDP, then TCP when truncated): for
/// forward zones, which only the local network knows.
pub async fn plain(server: SocketAddr, wire: &[u8]) -> Result<Vec<u8>, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let id = u16::from_be_bytes([
        *wire.first().ok_or("empty query")?,
        *wire.get(1).ok_or("short query")?,
    ]);
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = tokio::net::UdpSocket::bind(bind)
        .await
        .map_err(|e| e.to_string())?;
    sock.connect(server).await.map_err(|e| e.to_string())?;
    sock.send(wire).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 4096];
    let udp = async {
        loop {
            let n = sock.recv(&mut buf).await.map_err(|e| e.to_string())?;
            if n >= 12 && u16::from_be_bytes([buf[0], buf[1]]) == id {
                return Ok::<_, String>(buf[..n].to_vec());
            }
        }
    };
    let r = tokio::time::timeout(Duration::from_secs(3), udp)
        .await
        .map_err(|_| format!("{server}: no answer"))??;
    if r[2] & 0x02 == 0 {
        return Ok(r);
    }
    // truncated: the same question over TCP
    let tcp = async {
        let mut c = tokio::net::TcpStream::connect(server)
            .await
            .map_err(|e| e.to_string())?;
        let mut out = (wire.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(wire);
        c.write_all(&out).await.map_err(|e| e.to_string())?;
        let n = c.read_u16().await.map_err(|e| e.to_string())? as usize;
        let mut b = vec![0u8; n];
        c.read_exact(&mut b).await.map_err(|e| e.to_string())?;
        Ok::<_, String>(b)
    };
    tokio::time::timeout(Duration::from_secs(5), tcp)
        .await
        .map_err(|_| format!("{server}: no answer over TCP"))?
}

impl Resolve for Bootstrap {
    fn resolve(&self, name: reqwest::dns::Name) -> Resolving {
        let me = self.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            let ips = me
                .lookup(&host)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            let addrs: Addrs = Box::new(ips.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

pub fn rand_u16() -> u16 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    h.finish() as u16
}

// ---------------------------------------------------------------- upstream

pub struct Upstream {
    http: reqwest::Client,
    primary: String,
    fallback: Vec<String>,
    /// while EnclaveDNS is unreachable, go straight to the fallback (ms since start)
    primary_down_until: AtomicU64,
    started: Instant,
    pub stats: Mutex<UpstreamStats>,
}

#[derive(Default, Clone, Debug, serde::Serialize)]
pub struct UpstreamStats {
    pub primary_answers: u64,
    pub primary_failures: u64,
    pub fallback_answers: u64,
    pub fallback_failures: u64,
    pub last_primary_error: Option<String>,
    pub primary_srtt_ms: u64,
}

/// How long EnclaveDNS gets before a question goes to the fallback. ENS
/// lookups behind it can take a few seconds when nothing is cached.
const PRIMARY_WAIT: Duration = Duration::from_secs(7);
const FALLBACK_WAIT: Duration = Duration::from_secs(5);
/// After EnclaveDNS fails, how long to skip it (it is retried after).
const PRIMARY_HOLD: Duration = Duration::from_secs(20);

pub enum Via {
    Primary,
    Fallback,
}

impl Upstream {
    pub fn new(cfg: &Config, boot: Bootstrap) -> Upstream {
        let http = reqwest::Client::builder()
            .user_agent(concat!("enclavedns-client/", env!("CARGO_PKG_VERSION")))
            .dns_resolver(Arc::new(boot))
            .connect_timeout(Duration::from_secs(5))
            .pool_idle_timeout(Duration::from_secs(55))
            .pool_max_idle_per_host(16)
            .build()
            .expect("http client");
        Upstream {
            http,
            primary: cfg.doh_url(),
            fallback: cfg.fallback.clone(),
            primary_down_until: AtomicU64::new(0),
            started: Instant::now(),
            stats: Mutex::default(),
        }
    }

    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }

    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    pub fn primary_down(&self) -> bool {
        self.now_ms() < self.primary_down_until.load(Ordering::Relaxed)
    }

    async fn doh(&self, url: &str, q: &[u8], wait: Duration) -> Result<Vec<u8>, String> {
        let r = self
            .http
            .post(url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(q.to_vec())
            .timeout(wait)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !r.status().is_success() {
            return Err(format!("HTTP {}", r.status()));
        }
        let b = r.bytes().await.map_err(|e| e.to_string())?;
        if b.len() < 12 {
            return Err("short DNS answer".into());
        }
        Ok(b.to_vec())
    }

    /// Ask EnclaveDNS; on a transport failure (never on a DNS answer), the
    /// fallbacks, unless `primary_only` (names only EnclaveDNS can answer).
    pub async fn query(&self, q: &[u8], primary_only: bool) -> Result<(Vec<u8>, Via), String> {
        let mut err = String::new();
        if primary_only || !self.primary_down() || self.fallback.is_empty() {
            let t0 = Instant::now();
            match self.doh(&self.primary, q, PRIMARY_WAIT).await {
                Ok(b) => {
                    let mut s = self.stats.lock().unwrap();
                    s.primary_answers += 1;
                    let ms = t0.elapsed().as_millis() as u64;
                    s.primary_srtt_ms = if s.primary_srtt_ms == 0 {
                        ms
                    } else {
                        (s.primary_srtt_ms * 7 + ms) / 8
                    };
                    drop(s);
                    self.primary_down_until.store(0, Ordering::Relaxed);
                    return Ok((b, Via::Primary));
                }
                Err(e) => {
                    let mut s = self.stats.lock().unwrap();
                    s.primary_failures += 1;
                    s.last_primary_error = Some(e.clone());
                    drop(s);
                    self.primary_down_until.store(
                        self.now_ms() + PRIMARY_HOLD.as_millis() as u64,
                        Ordering::Relaxed,
                    );
                    err = format!("EnclaveDNS: {e}");
                }
            }
        }
        if primary_only {
            return Err(err);
        }
        for f in &self.fallback {
            match self.doh(f, q, FALLBACK_WAIT).await {
                Ok(b) => {
                    self.stats.lock().unwrap().fallback_answers += 1;
                    return Ok((b, Via::Fallback));
                }
                Err(e) => {
                    self.stats.lock().unwrap().fallback_failures += 1;
                    err = format!("{err}; {f}: {e}");
                }
            }
        }
        Err(err)
    }
}
