//! Asking the running client things, with no other tools installed.

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// One question over UDP; the answer as dig-like lines.
pub async fn dns(server: SocketAddr, name: &str, qtype: &str) -> Result<Vec<String>, String> {
    let t = RecordType::from_str(&qtype.to_ascii_uppercase())
        .map_err(|_| format!("unknown record type {qtype}"))?;
    let n = Name::from_ascii(if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    })
    .map_err(|e| e.to_string())?;
    let mut m = Message::new();
    let id = enclavedns_core::upstream::rand_u16();
    m.set_id(id)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true);
    m.add_query(Query::query(n, t));
    let wire = m.to_vec().map_err(|e| e.to_string())?;
    let b = enclavedns_core::upstream::plain(server, &wire)
        .await
        .map_err(|e| format!("{e} (is the client running? `enclavedns status`)"))?;
    let r = Message::from_vec(&b).map_err(|e| e.to_string())?;
    let mut out = vec![format!(
        ";; {:?}{} from {server}",
        r.response_code(),
        if r.authentic_data() {
            ", DNSSEC validated (AD)"
        } else {
            ""
        }
    )];
    for rec in r.answers() {
        out.push(rec.to_string());
    }
    if r.answers().is_empty() {
        for rec in r.name_servers() {
            out.push(format!("; {rec}"));
        }
    }
    Ok(out)
}

/// A plain HTTP/1.0 GET of a local endpoint; the body.
pub async fn http_get(host: &str, port: u16, path: &str) -> Result<String, String> {
    let addr = format!("{host}:{port}");
    let f = async {
        let mut c = tokio::net::TcpStream::connect(&addr)
            .await
            .map_err(|e| e.to_string())?;
        c.write_all(format!("GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n").as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let mut b = Vec::new();
        c.read_to_end(&mut b).await.map_err(|e| e.to_string())?;
        let s = String::from_utf8_lossy(&b).to_string();
        let (head, body) = s.split_once("\r\n\r\n").ok_or("bad HTTP answer")?;
        if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
            return Err(head.lines().next().unwrap_or("").to_string());
        }
        Ok(body.to_string())
    };
    tokio::time::timeout(Duration::from_secs(15), f)
        .await
        .map_err(|_| format!("{addr}: no answer"))?
}
