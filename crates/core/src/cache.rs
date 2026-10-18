//! Answers kept for their TTL, so a repeated name costs no trip to
//! EnclaveDNS (each one crosses the internet to an attested enclave).

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Hash, PartialEq, Eq, Clone)]
pub struct Key {
    name: String,
    qtype: u16,
    qclass: u16,
    cd: bool,
    dnssec_ok: bool,
}

impl Key {
    pub fn of(q: &Message) -> Option<Key> {
        let question = q.queries().first()?;
        Some(Key {
            name: question.name().to_lowercase().to_ascii(),
            qtype: u16::from(question.query_type()),
            qclass: u16::from(question.query_class()),
            cd: q.checking_disabled(),
            dnssec_ok: q.extensions().as_ref().is_some_and(|e| e.dnssec_ok()),
        })
    }
}

struct Entry {
    stored: Instant,
    ttl: u32,
    msg: Message,
}

pub struct Cache {
    max: usize,
    map: Mutex<HashMap<Key, Entry>>,
}

const MAX_TTL: u32 = 86_400;
const MAX_NEGATIVE_TTL: u32 = 3_600;

impl Cache {
    pub fn new(max: usize) -> Cache {
        Cache {
            max,
            map: Mutex::default(),
        }
    }

    pub fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A cached answer with its TTLs aged, for a query with id `id`.
    pub fn get(&self, key: &Key, id: u16) -> Option<Message> {
        let mut m = self.map.lock().unwrap();
        let e = m.get(key)?;
        let age = e.stored.elapsed().as_secs() as u32;
        if age >= e.ttl {
            m.remove(key);
            return None;
        }
        let mut msg = e.msg.clone();
        msg.set_id(id);
        let age_all = |rs: &mut Vec<hickory_proto::rr::Record>| {
            for r in rs.iter_mut() {
                r.set_ttl(r.ttl().saturating_sub(age));
            }
        };
        let (mut ans, mut auth, mut add) = (
            msg.take_answers(),
            msg.take_name_servers(),
            msg.take_additionals(),
        );
        age_all(&mut ans);
        age_all(&mut auth);
        age_all(&mut add);
        msg.insert_answers(ans);
        msg.insert_name_servers(auth);
        msg.insert_additionals(add);
        Some(msg)
    }

    pub fn put(&self, key: Key, msg: &Message) {
        let Some(ttl) = cache_ttl(msg) else { return };
        let mut m = self.map.lock().unwrap();
        if m.len() >= self.max {
            let now = Instant::now();
            m.retain(|_, e| now.duration_since(e.stored) < Duration::from_secs(e.ttl as u64));
            if m.len() >= self.max {
                m.clear();
            }
        }
        m.insert(
            key,
            Entry {
                stored: Instant::now(),
                ttl,
                msg: msg.clone(),
            },
        );
    }
}

/// How long `msg` may be kept: the smallest TTL in it; for a negative
/// answer the SOA's (RFC 2308). None = do not keep.
fn cache_ttl(msg: &Message) -> Option<u32> {
    if msg.truncated() {
        return None;
    }
    let rc = msg.response_code();
    if rc != ResponseCode::NoError && rc != ResponseCode::NXDomain {
        return None;
    }
    let records = msg
        .answers()
        .iter()
        .chain(msg.name_servers())
        .filter(|r| r.record_type() != RecordType::OPT);
    let ttl = records.map(|r| r.ttl()).min();
    let negative = msg.answers().is_empty();
    let ttl = match (ttl, negative) {
        (Some(t), false) => t.min(MAX_TTL),
        (Some(t), true) => {
            let soa_min = msg.name_servers().iter().find_map(|r| match r.data() {
                Some(hickory_proto::rr::RData::SOA(s)) => Some(s.minimum()),
                _ => None,
            });
            t.min(soa_min.unwrap_or(t)).min(MAX_NEGATIVE_TTL)
        }
        // a negative answer with no SOA: keep it briefly
        (None, true) => 30,
        (None, false) => return None,
    };
    (ttl > 0).then_some(ttl)
}
