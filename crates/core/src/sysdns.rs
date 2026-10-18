//! This machine's own DNS servers: the fallback while EnclaveDNS cannot be
//! reached (unless the config is strict). Never loopback: after `enable`
//! that would be this client itself.

use std::net::{IpAddr, SocketAddr};

fn keep(ip: IpAddr, out: &mut Vec<SocketAddr>) {
    if ip.is_loopback() || ip.is_unspecified() {
        return;
    }
    // fec0::/10 (deprecated site-local): Windows lists fec0:0:0:ffff::1-3 as
    // placeholder DNS on adapters that have none; nothing answers there
    if let IpAddr::V6(v6) = ip {
        if v6.segments()[0] & 0xffc0 == 0xfec0 {
            return;
        }
    }
    let a = SocketAddr::new(ip, 53);
    if !out.contains(&a) {
        out.push(a);
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn nameservers(text: &str, out: &mut Vec<SocketAddr>) {
    for line in text.lines() {
        let mut w = line.split_whitespace();
        if w.next() == Some("nameserver") {
            if let Some(ip) = w
                .next()
                .and_then(|s| s.split('%').next())
                .and_then(|s| s.parse().ok())
            {
                keep(ip, out);
            }
        }
    }
}

/// The servers the network gave this machine, found now.
pub fn discover() -> Vec<SocketAddr> {
    #[allow(unused_mut)] // Android: the app reports the network's servers itself
    let mut out = Vec::new();
    #[cfg(target_os = "linux")]
    {
        // systemd-resolved's own upstreams (not its 127.0.0.53 stub)
        if let Ok(t) = std::fs::read_to_string("/run/systemd/resolve/resolv.conf") {
            nameservers(&t, &mut out);
        }
        if out.is_empty() {
            if let Ok(o) = std::process::Command::new("nmcli")
                .args(["-t", "-f", "IP4.DNS,IP6.DNS", "device", "show"])
                .output()
            {
                for line in String::from_utf8_lossy(&o.stdout).lines() {
                    if let Some((_, v)) = line.split_once(':') {
                        if let Ok(ip) = v.trim().replace("\\:", ":").parse::<IpAddr>() {
                            keep(ip, &mut out);
                        }
                    }
                }
            }
        }
        if out.is_empty() {
            // no resolved, no NetworkManager: what `enable` recorded, else resolv.conf (before `enable`)
            if let Ok(t) = std::fs::read_to_string("/etc/enclavedns/network-dns") {
                for l in t.lines() {
                    if let Ok(ip) = l.trim().parse::<IpAddr>() {
                        keep(ip, &mut out);
                    }
                }
            }
            if out.is_empty() {
                if let Ok(t) = std::fs::read_to_string("/etc/resolv.conf") {
                    nameservers(&t, &mut out);
                }
            }
        }
    }
    #[cfg(windows)]
    {
        // the adapters' servers: the NRPT rule that sends names to this client leaves them as they are
        let script = "Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses } | ForEach-Object { $_.ServerAddresses }";
        if let Ok(o) = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
        {
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                if let Ok(ip) = line
                    .trim()
                    .split('%')
                    .next()
                    .unwrap_or("")
                    .parse::<IpAddr>()
                {
                    keep(ip, &mut out);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_skips_loopback() {
        let mut v = Vec::new();
        nameservers("# x\nnameserver 127.0.0.53\nnameserver 192.168.8.1\nnameserver fe80::1%eth0\nnameserver ::1\nnameserver fec0:0:0:ffff::1\n", &mut v);
        assert_eq!(
            v,
            vec![
                "192.168.8.1:53".parse().unwrap(),
                "[fe80::1]:53".parse().unwrap()
            ]
        );
    }
}
