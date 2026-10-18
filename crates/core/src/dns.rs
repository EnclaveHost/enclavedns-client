//! The stub resolver: every DNS question this machine asks.
//!
//! * Everything goes to EnclaveDNS over DoH, through a cache. Only when
//!   EnclaveDNS cannot be reached at all (and the config is not strict) does
//!   a question go to this machine's own DNS, then any DoH fallbacks: an
//!   answer from EnclaveDNS, SERVFAIL included (that is how a DNSSEC failure
//!   looks), is final.
//! * `.eth` and `.ens` exist only in EnclaveDNS, so they never go to the
//!   fallback. An `A` question about such a name that holds no address
//!   records (content, a `url`, only a wallet) is answered with the gateway
//!   address, where this client serves the site or says what is missing.
//!   If EnclaveDNS is unreachable it gets the gateway too (briefly), so the
//!   browser shows a page saying so.
//! * `use-application-dns.net` is NXDOMAIN: Firefox's signal to keep its own
//!   DoH off and use the system resolver (this one).

use crate::cache::Key;
use crate::Engine;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// A special-use name (RFC 6761 .invalid) only this client answers: its
/// TXT record says "enclavedns-client=<version>". Probes ask it to know
/// they reached the client and not some other resolver on port 53.
pub const IDENTITY_NAME: &str = "enclavedns-client.invalid.";

pub fn identity() -> String {
    format!("enclavedns-client={}", env!("CARGO_PKG_VERSION"))
}

const SYNTH_TTL: u32 = 60;
const UNREACHABLE_TTL: u32 = 5;
const MAX_UDP: usize = 1232;

pub async fn serve_udp(sock: UdpSocket, e: Arc<Engine>) {
    let sock = Arc::new(sock);
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf).await else {
            continue;
        };
        let q = buf[..n].to_vec();
        let (sock, e) = (sock.clone(), e.clone());
        tokio::spawn(async move {
            if let Some(r) = answer_udp(&e, &q).await {
                let _ = sock.send_to(&r, from).await;
            }
        });
    }
}

pub async fn serve_tcp(l: TcpListener, e: Arc<Engine>) {
    loop {
        let Ok((c, _)) = l.accept().await else {
            continue;
        };
        let e = e.clone();
        tokio::spawn(async move { serve_tcp_stream(c, e).await });
    }
}

/// DNS over one TCP stream (also used for the Android VPN's streams).
pub async fn serve_tcp_stream<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut c: S,
    e: Arc<Engine>,
) {
    loop {
        let Ok(Ok(len)) =
            tokio::time::timeout(std::time::Duration::from_secs(30), c.read_u16()).await
        else {
            return;
        };
        let mut q = vec![0u8; len as usize];
        if c.read_exact(&mut q).await.is_err() {
            return;
        }
        let Some(r) = answer(&e, &q).await else {
            return;
        };
        let mut out = (r.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&r);
        if c.write_all(&out).await.is_err() {
            return;
        }
    }
}

/// An answer that fits a UDP reply: too big = truncated, so the client
/// retries over TCP.
pub async fn answer_udp(e: &Engine, wire: &[u8]) -> Option<Vec<u8>> {
    let r = answer(e, wire).await?;
    let limit = Message::from_vec(wire)
        .ok()
        .and_then(|q| q.extensions().as_ref().map(|x| x.max_payload() as usize))
        .unwrap_or(512)
        .clamp(512, MAX_UDP);
    if r.len() <= limit {
        return Some(r);
    }
    let q = Message::from_vec(wire).ok()?;
    let mut t = reply(&q, ResponseCode::NoError);
    t.set_truncated(true);
    t.to_vec().ok()
}

fn lower(n: &Name) -> String {
    n.to_lowercase().to_ascii()
}

pub fn is_ens(n: &Name) -> bool {
    let s = lower(n);
    s.ends_with(".eth.") || s.ends_with(".ens.") || s == "eth." || s == "ens."
}

fn reply(q: &Message, rc: ResponseCode) -> Message {
    let mut m = Message::new();
    m.set_id(q.id())
        .set_message_type(MessageType::Response)
        .set_op_code(q.op_code())
        .set_recursion_desired(q.recursion_desired())
        .set_recursion_available(true)
        .set_response_code(rc);
    m.add_queries(q.queries().to_vec());
    m
}

fn gateway_record(name: Name, ip: IpAddr, ttl: u32) -> Option<Record> {
    match ip {
        IpAddr::V4(v4) => Some(Record::from_rdata(name, ttl, RData::A(A(v4)))),
        IpAddr::V6(v6) => Some(Record::from_rdata(name, ttl, RData::AAAA(AAAA(v6)))),
    }
}

/// The answer to one DNS message, or None to drop it.
pub async fn answer(e: &Engine, wire: &[u8]) -> Option<Vec<u8>> {
    let q = Message::from_vec(wire).ok()?;
    if q.message_type() != MessageType::Query {
        return None;
    }
    let Some(question) = q.queries().first().cloned() else {
        return reply(&q, ResponseCode::FormErr).to_vec().ok();
    };
    let qname = question.name().clone();
    if lower(&qname) == "use-application-dns.net." {
        return reply(&q, ResponseCode::NXDomain).to_vec().ok();
    }
    if lower(&qname) == IDENTITY_NAME {
        // proves THIS client answers (not another resolver on the same port,
        // e.g. Windows' Internet Connection Sharing proxy on 0.0.0.0:53)
        let mut m = reply(&q, ResponseCode::NoError);
        if question.query_type() == RecordType::TXT {
            m.add_answer(Record::from_rdata(
                qname,
                0,
                RData::TXT(hickory_proto::rr::rdata::TXT::new(vec![identity()])),
            ));
        }
        return m.to_vec().ok();
    }
    let key = Key::of(&q);
    if let Some(k) = &key {
        if let Some(m) = e.cache.get(k, q.id()) {
            e.counters.lock().unwrap().cached += 1;
            return m.to_vec().ok();
        }
    }
    let lname = lower(&qname);
    if let Some(f) = e
        .cfg
        .forward
        .iter()
        .filter(|f| f.covers(&lname))
        .max_by_key(|f| f.zone.len())
    {
        // a name only the local network knows
        for s in &f.servers {
            if let Ok(mut b) = crate::upstream::plain(*s, wire).await {
                e.counters.lock().unwrap().forwarded += 1;
                b[0..2].copy_from_slice(&q.id().to_be_bytes());
                return Some(b);
            }
        }
        return reply(&q, ResponseCode::ServFail).to_vec().ok();
    }
    let ens = is_ens(&qname);
    let qtype = question.query_type();
    let gw_type = if e.cfg.gateway.is_ipv4() {
        RecordType::A
    } else {
        RecordType::AAAA
    };
    let r = e.up.query(wire, ens).await;
    {
        let mut c = e.counters.lock().unwrap();
        match &r {
            Ok((_, crate::upstream::Via::Primary)) => c.enclavedns += 1,
            Ok((_, crate::upstream::Via::System)) => c.system += 1,
            Ok((_, crate::upstream::Via::Fallback)) => c.fallback += 1,
            Err(_) => c.failed += 1,
        }
    }
    let mut r = match r.ok().and_then(|(b, _)| Message::from_vec(&b).ok()) {
        Some(r) => r,
        None if ens && qtype == gw_type => {
            // EnclaveDNS is unreachable: the browser gets the page that says so
            let mut m = reply(&q, ResponseCode::NoError);
            m.add_answer(gateway_record(qname, e.cfg.gateway, UNREACHABLE_TTL)?);
            return m.to_vec().ok();
        }
        None => return reply(&q, ResponseCode::ServFail).to_vec().ok(),
    };
    r.set_id(q.id());
    if ens && qtype == gw_type && r.response_code() == ResponseCode::NoError {
        // follow the CNAME chain inside the answer (`.ens` aliases to `.eth`)
        let mut name = qname.to_lowercase();
        for _ in 0..8 {
            let next = r.answers().iter().find_map(|rec| match rec.data() {
                Some(RData::CNAME(c)) if rec.name().to_lowercase() == name => {
                    Some(c.0.to_lowercase())
                }
                _ => None,
            });
            match next {
                Some(n) => name = n,
                None => break,
            }
        }
        let has_addr = r
            .answers()
            .iter()
            .any(|rec| rec.record_type() == gw_type && rec.name().to_lowercase() == name);
        if !has_addr && is_ens(&name) {
            r.add_answer(gateway_record(name, e.cfg.gateway, SYNTH_TTL)?);
            r.set_authentic_data(false);
        }
    }
    if let Some(k) = key {
        e.cache.put(k, &r);
    }
    r.to_vec().ok()
}
