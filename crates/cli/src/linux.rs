//! `enable`/`disable` on Linux: system DNS and the .eth CA.
//!
//! enable:
//!  1. the client must already answer on 127.0.0.1:53 (the service runs it)
//!  2. names only the local network knows (the network's search domains, e.g.
//!     `lan`) are forwarded to the network's own DNS servers, and a local
//!     kubo's addresses are taken from the invoking user's ~/.ipfs/config:
//!     both written into a managed block of the config file
//!  3. the .eth CA is added to the system trust store
//!  4. NetworkManager (if running) stops writing /etc/resolv.conf, and
//!     /etc/resolv.conf points at the client; the old one is kept
//! Everything changed is recorded in /var/lib/enclavedns-system/state.json,
//! and disable puts each thing back.

use crate::{probe, Ctx};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

const SYS: &str = "/var/lib/enclavedns-system";
const NM_CONF: &str = "/etc/NetworkManager/conf.d/90-enclavedns-client.conf";
const RESOLV: &str = "/etc/resolv.conf";
const BLOCK_START: &str = "# --- managed by `enclavedns enable` (rewritten on each enable) ---";
const BLOCK_END: &str = "# --- end of managed block ---";

fn sh(cmd: &str, args: &[&str]) -> Result<String, String> {
    let o = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("{cmd}: {e}"))?;
    if !o.status.success() {
        return Err(format!(
            "{cmd} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&o.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&o.stdout).to_string())
}

fn is_root() -> bool {
    sh("id", &["-u"]).map(|s| s.trim() == "0").unwrap_or(false)
}

fn active(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
        .is_ok_and(|s| s.success())
}

/// Where this distribution keeps local trust anchors, and how to refresh.
fn trust_store() -> Option<(PathBuf, &'static str, &'static [&'static str])> {
    let options: [(&str, &str, &str, &[&str]); 3] = [
        (
            "/etc/ca-certificates/trust-source/anchors",
            "enclavedns-eth-ca.crt",
            "update-ca-trust",
            &[],
        ),
        (
            "/etc/pki/ca-trust/source/anchors",
            "enclavedns-eth-ca.crt",
            "update-ca-trust",
            &["extract"],
        ),
        (
            "/usr/local/share/ca-certificates",
            "enclavedns-eth-ca.crt",
            "update-ca-certificates",
            &[],
        ),
    ];
    for (dir, file, cmd, args) in options {
        if Path::new(dir).is_dir() {
            return Some((Path::new(dir).join(file), cmd, args));
        }
    }
    None
}

#[derive(Default)]
struct Network {
    servers: Vec<SocketAddr>,
    domains: Vec<String>,
}

fn is_loopback(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>()
        .is_ok_and(|a| a.is_loopback())
}

/// The network's own DNS servers and search domains: from NetworkManager
/// (it knows them even while it leaves resolv.conf alone), else from the
/// current resolv.conf or the one saved before an earlier takeover.
fn network() -> Network {
    let mut n = Network::default();
    if let Ok(out) = sh(
        "nmcli",
        &[
            "-t",
            "-f",
            "IP4.DNS,IP6.DNS,IP4.DOMAIN,IP6.DOMAIN",
            "device",
            "show",
        ],
    ) {
        for line in out.lines() {
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            let v = v.trim().replace("\\:", ":");
            if k.contains(".DNS") && !is_loopback(&v) {
                if let Ok(ip) = v.parse::<std::net::IpAddr>() {
                    let a = SocketAddr::new(ip, 53);
                    if !n.servers.contains(&a) {
                        n.servers.push(a);
                    }
                }
            } else if k.contains(".DOMAIN") && !v.is_empty() && !n.domains.contains(&v) {
                n.domains.push(v);
            }
        }
    }
    for f in [
        RESOLV.to_string(),
        format!("{SYS}/resolv.conf.saved"),
        "/etc/resolv.conf.before-enclavedns".to_string(),
    ] {
        let Ok(t) = fs::read_to_string(&f) else {
            continue;
        };
        for line in t.lines() {
            let mut w = line.split_whitespace();
            match w.next() {
                Some("nameserver") => {
                    if let Some(ip) = w
                        .next()
                        .filter(|ip| !is_loopback(ip))
                        .and_then(|ip| ip.parse::<std::net::IpAddr>().ok())
                    {
                        let a = SocketAddr::new(ip, 53);
                        if !n.servers.contains(&a) {
                            n.servers.push(a);
                        }
                    }
                }
                Some("search") | Some("domain") => {
                    for d in w {
                        if !n.domains.iter().any(|x| x == d) {
                            n.domains.push(d.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
    }
    // only private networks' servers: a public resolver is no local zone's authority
    n.servers.retain(|a| match a.ip() {
        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        std::net::IpAddr::V6(v6) => {
            (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    });
    n
}

/// kubo's gateway and API from the invoking user's ~/.ipfs/config.
fn kubo() -> Option<(String, String)> {
    let user = std::env::var("SUDO_USER").ok()?;
    let home = sh("getent", &["passwd", &user])
        .ok()?
        .split(':')
        .nth(5)?
        .to_string();
    let cfg: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(format!("{home}/.ipfs/config")).ok()?).ok()?;
    let url = |v: &serde_json::Value| -> Option<String> {
        let m = v.as_str().or_else(|| v.as_array()?.first()?.as_str())?;
        let p: Vec<&str> = m.split('/').collect();
        (p.len() >= 5 && (p[1] == "ip4" || p[1] == "ip6") && p[3] == "tcp")
            .then(|| format!("http://{}:{}", p[2], p[4]))
    };
    Some((
        url(&cfg["Addresses"]["Gateway"])?,
        url(&cfg["Addresses"]["API"])?,
    ))
}

fn write_managed_block(
    config: &Path,
    net: &Network,
    kubo: Option<(String, String)>,
) -> Result<String, String> {
    let old = fs::read_to_string(config).unwrap_or_default();
    let kept = match (old.find(BLOCK_START), old.find(BLOCK_END)) {
        (Some(a), Some(b)) if b > a => format!("{}{}", &old[..a], &old[b + BLOCK_END.len()..]),
        _ => old.clone(),
    };
    let kept = kept.trim_end().to_string();
    let mut block = format!("{BLOCK_START}\n");
    let mut said = Vec::new();
    if !net.servers.is_empty() {
        let servers: Vec<String> = net.servers.iter().map(|s| format!("\"{s}\"")).collect();
        for d in &net.domains {
            block.push_str(&format!(
                "[[forward]]\nzone = \"{d}\"\nservers = [{}]\n\n",
                servers.join(", ")
            ));
            said.push(format!(
                "*.{d} -> {}",
                net.servers
                    .iter()
                    .map(|s| s.ip().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    if let Some((gw, api)) = kubo {
        if kept.lines().any(|l| l.trim() == "[backends]") {
            said.push("kubo: [backends] is set by hand, left alone".into());
        } else {
            block.push_str(&format!(
                "[backends]\nipfs = \"{gw}\"\nipfs_api = \"{api}\"\n\n"
            ));
            said.push(format!("kubo gateway {gw}"));
        }
    }
    block.push_str(BLOCK_END);
    let text = if kept.is_empty() {
        format!("{block}\n")
    } else {
        format!("{kept}\n\n{block}\n")
    };
    enclavedns_core::Config::from_toml(&text)
        .map_err(|e| format!("the config would not parse after the change: {e}"))?;
    if let Some(dir) = config.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    fs::write(config, text).map_err(|e| format!("{}: {e}", config.display()))?;
    Ok(if said.is_empty() {
        "nothing local to add".into()
    } else {
        said.join("; ")
    })
}

fn wait_answering(server: SocketAddr) -> bool {
    let rt = crate::runtime();
    for _ in 0..30 {
        if rt
            .block_on(probe::dns(server, "enclave.host", "A"))
            .is_ok_and(|l| l.first().is_some_and(|h| h.contains("NoError")))
        {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    false
}

fn our_resolv(cfg: &enclavedns_core::Config, net: &Network) -> String {
    let mut text = String::from(
        "# written by `enclavedns enable`; `sudo enclavedns disable` restores the previous file\n",
    );
    if !net.domains.is_empty() {
        text.push_str(&format!("search {}\n", net.domains.join(" ")));
    }
    for a in &cfg.dns_listen {
        text.push_str(&format!("nameserver {}\n", a.ip()));
    }
    text.push_str("options edns0 trust-ad timeout:3 attempts:2\n");
    text
}

/// Put the pre-`enable` resolv.conf back without forgetting it (the
/// watchdog's fail-open; `disable` also deletes the copy).
fn restore_saved_resolv() -> Result<(), String> {
    let link = format!("{SYS}/resolv.conf.link");
    let saved = format!("{SYS}/resolv.conf.saved");
    if let Ok(target) = fs::read_to_string(&link) {
        let _ = fs::remove_file(RESOLV);
        std::os::unix::fs::symlink(target.trim(), RESOLV).map_err(|e| e.to_string())
    } else if Path::new(&saved).exists() {
        let _ = fs::remove_file(RESOLV);
        fs::copy(&saved, RESOLV)
            .map(|_| ())
            .map_err(|e| e.to_string())
    } else {
        Err("no saved resolv.conf".into())
    }
}

fn write_ours(cfg: &enclavedns_core::Config) -> Result<(), String> {
    let text = our_resolv(cfg, &network());
    if fs::symlink_metadata(RESOLV).is_ok_and(|m| m.file_type().is_symlink()) {
        fs::remove_file(RESOLV).map_err(|e| e.to_string())?;
    }
    fs::write(RESOLV, text).map_err(|e| e.to_string())
}

const SUSPENDED: &str = "/var/lib/enclavedns-system/watchdog-suspended";

/// `enclavedns watchdog`, every minute (enclavedns-watchdog.timer): this
/// machine's DNS must never depend on a dead client. When the client stops
/// answering, restart it (killing it if it hangs); if it still does not
/// answer, put the network's resolv.conf back so DNS fails open; point it
/// at the client again once it answers.
pub fn watchdog(ctx: &Ctx) -> Result<(), String> {
    if !Path::new(&format!("{SYS}/state.json")).exists() {
        return Ok(());
    }
    let cfg = ctx.config();
    let dns = cfg
        .dns_listen
        .first()
        .copied()
        .ok_or("dns_listen is empty")?;
    let suspended = Path::new(SUSPENDED).exists();
    if !probe::alive(dns, 3) {
        println!("the client does not answer on {dns}: restarting enclavedns.service");
        let _ = sh(
            "systemctl",
            &["kill", "--signal=SIGKILL", "enclavedns.service"],
        );
        let _ = sh("systemctl", &["restart", "enclavedns.service"]);
        let mut back = false;
        for _ in 0..10 {
            std::thread::sleep(std::time::Duration::from_secs(2));
            if probe::alive(dns, 1) {
                back = true;
                break;
            }
        }
        if !back {
            if !suspended {
                restore_saved_resolv()?;
                fs::write(SUSPENDED, "the client did not answer; the network's resolv.conf is back (DNS fails open)\n").map_err(|e| e.to_string())?;
                println!("still no answer: /etc/resolv.conf is the network's again until the client answers");
            }
            return Ok(());
        }
        println!("the client answers again after a restart");
    }
    if suspended {
        write_ours(&cfg)?;
        let _ = fs::remove_file(SUSPENDED);
        println!("the client answers: /etc/resolv.conf points at it again");
    }
    Ok(())
}

pub fn enable(ctx: &Ctx) -> Result<(), String> {
    if !is_root() {
        return Err("run it as root: sudo enclavedns enable".into());
    }
    if Path::new("/etc/dnscrypt-proxy/undo-enclavedns.sh").exists() {
        return Err(
            "the earlier dnscrypt-proxy setup is still installed; remove it first: \
sudo bash /etc/dnscrypt-proxy/undo-enclavedns.sh"
                .into(),
        );
    }
    let cfg = ctx.config();
    let dns = cfg
        .dns_listen
        .first()
        .copied()
        .ok_or("dns_listen is empty")?;
    fs::create_dir_all(SYS).map_err(|e| e.to_string())?;
    let _ = sh("chmod", &["0700", SYS]);

    println!("== 1/4 the client answers on {dns}");
    if !wait_answering(dns) {
        return Err(format!("nothing answers on {dns}; start the service first: sudo systemctl enable --now enclavedns"));
    }

    println!("== 2/4 local names and local software");
    let net = network();
    let said = write_managed_block(&ctx.config_path, &net, kubo())?;
    println!("   {said}");
    let _ = sh("systemctl", &["try-restart", "enclavedns.service"]);
    if !wait_answering(dns) {
        return Err(
            "the client did not come back after the config change (journalctl -u enclavedns)"
                .into(),
        );
    }

    println!("== 3/4 trust the .eth CA");
    let ca = ctx.state_dir.join(enclavedns_core::tls::CA_CERT);
    let mut state = serde_json::json!({});
    match (fs::read_to_string(&ca), trust_store()) {
        (Ok(pem), Some((anchor, cmd, args))) => {
            fs::write(&anchor, pem).map_err(|e| format!("{}: {e}", anchor.display()))?;
            sh(cmd, args)?;
            state["ca_anchor"] = anchor.display().to_string().into();
            println!(
                "   trusted ({}); restart your browser to load it",
                anchor.display()
            );
        }
        (Err(e), _) => println!(
            "   skipped: {}: {e} (HTTPS for .eth stays off)",
            ca.display()
        ),
        (_, None) => println!(
            "   skipped: no system trust store found; trust {} by hand",
            ca.display()
        ),
    }

    println!("== 4/4 point this machine's DNS at the client");
    let saved = format!("{SYS}/resolv.conf.saved");
    let meta = fs::symlink_metadata(RESOLV).map_err(|e| e.to_string())?;
    if !Path::new(&saved).exists() && !Path::new(&format!("{SYS}/resolv.conf.link")).exists() {
        if meta.file_type().is_symlink() {
            let target = fs::read_link(RESOLV).map_err(|e| e.to_string())?;
            fs::write(
                format!("{SYS}/resolv.conf.link"),
                target.display().to_string(),
            )
            .map_err(|e| e.to_string())?;
        } else {
            fs::copy(RESOLV, &saved).map_err(|e| e.to_string())?;
        }
    }
    if active("NetworkManager.service") {
        fs::write(NM_CONF, "# written by `enclavedns enable`: NetworkManager leaves /etc/resolv.conf alone\n[main]\ndns=none\nrc-manager=unmanaged\n")
            .map_err(|e| e.to_string())?;
        sh("systemctl", &["reload", "NetworkManager.service"])?;
        state["networkmanager"] = true.into();
    }
    let text = our_resolv(&cfg, &net);
    if meta.file_type().is_symlink() {
        fs::remove_file(RESOLV).map_err(|e| e.to_string())?;
    }
    fs::write(RESOLV, text).map_err(|e| e.to_string())?;
    state["resolv"] = true.into();
    fs::write(
        format!("{SYS}/state.json"),
        serde_json::to_vec_pretty(&state).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    let _ = fs::remove_file(SUSPENDED);
    if sh(
        "systemctl",
        &["enable", "--now", "enclavedns-watchdog.timer"],
    )
    .is_ok()
    {
        println!(
            "   watchdog on: if the client stops answering, DNS falls back to the network's own"
        );
    }

    match sh("getent", &["hosts", "enclave.host"]) {
        Ok(o) if !o.trim().is_empty() => println!(
            "DONE: this machine resolves through EnclaveDNS (enclave.host -> {})",
            o.split_whitespace().next().unwrap_or("?")
        ),
        _ => println!(
            "WARNING: enclave.host did not resolve through the system; check `enclavedns status`"
        ),
    }
    Ok(())
}

pub fn disable(_ctx: &Ctx) -> Result<(), String> {
    if !is_root() {
        return Err("run it as root: sudo enclavedns disable".into());
    }
    let state: serde_json::Value = fs::read(format!("{SYS}/state.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    if let Some(a) = state["ca_anchor"].as_str() {
        let _ = fs::remove_file(a);
        if let Some((_, cmd, args)) = trust_store() {
            let _ = sh(cmd, args);
        }
        println!("CA no longer trusted");
    }
    let _ = fs::remove_file(NM_CONF);
    let link = format!("{SYS}/resolv.conf.link");
    let saved = format!("{SYS}/resolv.conf.saved");
    if let Ok(target) = fs::read_to_string(&link) {
        let _ = fs::remove_file(RESOLV);
        std::os::unix::fs::symlink(target.trim(), RESOLV).map_err(|e| e.to_string())?;
        let _ = fs::remove_file(&link);
    } else if Path::new(&saved).exists() {
        fs::copy(&saved, RESOLV).map_err(|e| e.to_string())?;
        let _ = fs::remove_file(&saved);
    }
    if active("NetworkManager.service") {
        let _ = sh("systemctl", &["reload", "NetworkManager.service"]);
        let _ = sh("nmcli", &["general", "reload", "dns-rc"]);
    }
    let _ = fs::remove_file(format!("{SYS}/state.json"));
    let _ = fs::remove_file(SUSPENDED);
    let _ = sh(
        "systemctl",
        &["disable", "--now", "enclavedns-watchdog.timer"],
    );
    println!("DONE: DNS is back to what it was before `enclavedns enable`");
    Ok(())
}

pub fn system_status() -> String {
    if Path::new(SUSPENDED).exists() {
        return "uses the NETWORK's DNS for now: the watchdog put the old resolv.conf back because the client stopped answering".into();
    }
    let t = fs::read_to_string(RESOLV).unwrap_or_default();
    if t.contains("`enclavedns enable`") {
        "uses the client (/etc/resolv.conf)".into()
    } else {
        "does NOT use the client yet (sudo enclavedns enable)".into()
    }
}
