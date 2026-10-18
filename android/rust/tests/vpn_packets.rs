//! The VPN path without a VPN: raw IPv4/UDP packets in, raw packets out,
//! through the same user-space stack the Android app uses.

use enclavedns_android::{android_config, serve_device, DNS_V4};
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn checksum(b: &[u8]) -> u16 {
    let mut s: u32 = 0;
    for c in b.chunks(2) {
        s += u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32;
    }
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

fn udp_packet(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, payload: &[u8]) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    let mut ip = vec![
        0x45,
        0,
        (total >> 8) as u8,
        total as u8,
        0,
        1,
        0x40,
        0,
        64,
        17,
        0,
        0,
    ];
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let c = checksum(&ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    let ulen = (8 + payload.len()) as u16;
    let mut udp = Vec::new();
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&dport.to_be_bytes());
    udp.extend_from_slice(&ulen.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    // UDP checksum over the pseudo-header
    let mut ph = Vec::new();
    ph.extend_from_slice(&src.octets());
    ph.extend_from_slice(&dst.octets());
    ph.extend_from_slice(&[0, 17]);
    ph.extend_from_slice(&ulen.to_be_bytes());
    ph.extend_from_slice(&udp);
    let c = checksum(&ph);
    udp[6..8].copy_from_slice(&c.to_be_bytes());
    ip.extend_from_slice(&udp);
    ip
}

fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = id.to_be_bytes().to_vec();
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for l in name.split('.') {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_over_the_vpn_device() {
    let dir = std::env::temp_dir().join(format!("enclavedns-android-test-{}", std::process::id()));
    let engine = enclavedns_core::Engine::new(android_config("").unwrap(), &dir).unwrap();
    let (mut phone, device) = tokio::io::duplex(65536);
    let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(serve_device(engine, device, stop_rx));

    let client = Ipv4Addr::new(10, 53, 0, 2);
    let pkt = udp_packet(
        client,
        40000,
        DNS_V4,
        53,
        &dns_query(0x1234, "use-application-dns.net"),
    );
    phone.write_all(&pkt).await.unwrap();
    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), phone.read(&mut buf))
        .await
        .expect("an answer packet")
        .unwrap();
    let r = &buf[..n];
    assert_eq!(r[9], 17, "a UDP packet");
    assert_eq!(&r[12..16], &DNS_V4.octets(), "from the VPN's DNS address");
    assert_eq!(&r[16..20], &client.octets(), "to the phone");
    let dns = &r[28..];
    assert_eq!(u16::from_be_bytes([dns[0], dns[1]]), 0x1234, "same DNS id");
    assert_eq!(dns[3] & 0x0f, 3, "NXDOMAIN: Firefox keeps its own DoH off");
    let _ = std::fs::remove_dir_all(&dir);
}
