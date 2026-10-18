//! What EnclaveDNS says: raw DNS over DoH, and what an ENS name holds
//! (`GET /api/ens/<name>`), remembered briefly.

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Deserialize, Clone, Debug, Default)]
pub struct Info {
    pub name: String,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub contenthash: Option<String>,
    #[serde(default)]
    pub text: HashMap<String, String>,
}

#[derive(Clone, Debug)]
pub enum Lookup {
    Found(Info),
    /// no ENS resolver for this name: it does not exist
    NoName,
    /// EnclaveDNS (or the chain behind it) did not answer
    Unreachable(String),
}

pub struct Ens {
    base: String,
    http: reqwest::Client,
    cache: Mutex<HashMap<String, (Instant, Lookup)>>,
}

const FOUND_FOR: Duration = Duration::from_secs(60);
const FAILED_FOR: Duration = Duration::from_secs(5);

impl Ens {
    /// `http` is the upstream client: it finds EnclaveDNS through the
    /// bootstrap resolver, never through the system (which is us).
    pub fn new(base: &str, http: reqwest::Client) -> Ens {
        Ens {
            base: base.to_string(),
            http,
            cache: Mutex::default(),
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    /// What `name` (a `.eth` name) holds.
    pub async fn info(&self, name: &str) -> Lookup {
        if let Some((at, l)) = self.cache.lock().unwrap().get(name) {
            let keep = if matches!(l, Lookup::Unreachable(_)) {
                FAILED_FOR
            } else {
                FOUND_FOR
            };
            if at.elapsed() < keep {
                return l.clone();
            }
        }
        let l = self.fetch(name).await;
        let mut c = self.cache.lock().unwrap();
        if c.len() > 4096 {
            c.clear();
        }
        c.insert(name.to_string(), (Instant::now(), l.clone()));
        l
    }

    async fn fetch(&self, name: &str) -> Lookup {
        let r = match self
            .http
            .get(format!("{}/api/ens/{name}", self.base))
            .timeout(Duration::from_secs(20))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => return Lookup::Unreachable(e.to_string()),
        };
        match r.status().as_u16() {
            200 => match r.json::<Info>().await {
                Ok(i) => Lookup::Found(i),
                Err(e) => Lookup::Unreachable(format!("unreadable answer: {e}")),
            },
            404 => Lookup::NoName,
            s => {
                let why = r
                    .json::<serde_json::Value>()
                    .await
                    .ok()
                    .and_then(|v| v["error"].as_str().map(str::to_string));
                Lookup::Unreachable(why.unwrap_or_else(|| format!("HTTP {s}")))
            }
        }
    }
}
