//! `enclavedns`: the EnclaveDNS client for Linux and Windows.

#[cfg(target_os = "linux")]
mod linux;
mod paths;
mod probe;
#[cfg(windows)]
mod windows;

use enclavedns_core::{Config, Engine};
use std::path::PathBuf;

const USAGE: &str =
    "enclavedns: this machine's DNS through EnclaveDNS, and .eth sites in the browser

usage: enclavedns [--config FILE] [--state DIR] <command>

  run                 run the client in the foreground (the service runs this)
  status              is it running, is this machine using it, what can it open
  enable              point this machine's DNS at the client and trust its
                      .eth-only CA for HTTPS (administrator/root)
  disable             undo `enable` (administrator/root)
  watchdog            one check, run every minute by the service's timer/task:
                      restart a client that stopped answering, and if it
                      stays down, give DNS back to the network until it answers
  query NAME [TYPE]   ask the client one question (default type A)
  ca                  print the .eth CA certificate (PEM) and where it lives
  version
";

#[cfg(windows)]
const SERVICE_USAGE: &str = "
  service install     register the Windows service (starts with Windows)
  service uninstall   remove it
  service start|stop
";

pub struct Ctx {
    pub config_path: PathBuf,
    pub state_dir: PathBuf,
}

impl Ctx {
    pub fn config(&self) -> Config {
        Config::load(&self.config_path).unwrap_or_else(|e| die(&e))
    }
}

pub fn die(msg: &str) -> ! {
    eprintln!("enclavedns: {msg}");
    std::process::exit(1)
}

fn usage() -> ! {
    eprint!("{USAGE}");
    #[cfg(windows)]
    eprint!("{SERVICE_USAGE}");
    std::process::exit(2)
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut ctx = Ctx {
        config_path: paths::config_file(),
        state_dir: paths::state_dir(),
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" if i + 1 < args.len() => {
                ctx.config_path = args.remove(i + 1).into();
                args.remove(i);
            }
            "--state" if i + 1 < args.len() => {
                ctx.state_dir = args.remove(i + 1).into();
                args.remove(i);
            }
            _ => i += 1,
        }
    }
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let rest = &args[args.len().min(1)..];
    match cmd {
        "run" => run(&ctx),
        "status" => status(&ctx),
        "query" => query(&ctx, rest),
        "ca" => ca(&ctx),
        "enable" => platform_enable(&ctx, true),
        "disable" => platform_enable(&ctx, false),
        "watchdog" => watchdog(&ctx),
        "version" | "--version" | "-V" => println!("enclavedns {}", env!("CARGO_PKG_VERSION")),
        #[cfg(windows)]
        "service" => windows::service(&ctx, rest),
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            #[cfg(windows)]
            print!("{SERVICE_USAGE}");
        }
        _ => usage(),
    }
}

pub fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

fn run(ctx: &Ctx) {
    let cfg = ctx.config();
    let e = Engine::new(cfg, &ctx.state_dir).unwrap_or_else(|e| die(&e));
    if let Err(e) = runtime().block_on(e.run()) {
        die(&e)
    }
}

fn platform_enable(ctx: &Ctx, on: bool) {
    #[cfg(target_os = "linux")]
    let r = if on {
        linux::enable(ctx)
    } else {
        linux::disable(ctx)
    };
    #[cfg(windows)]
    let r = if on {
        windows::enable(ctx)
    } else {
        windows::disable(ctx)
    };
    #[cfg(not(any(target_os = "linux", windows)))]
    let r: Result<(), String> = {
        let _ = (ctx, on);
        Err(
            "enable/disable exist on Linux and Windows; point your DNS at the client by hand"
                .into(),
        )
    };
    if let Err(e) = r {
        die(&e)
    }
}

fn watchdog(ctx: &Ctx) {
    #[cfg(target_os = "linux")]
    let r = linux::watchdog(ctx);
    #[cfg(windows)]
    let r = windows::watchdog(ctx);
    #[cfg(not(any(target_os = "linux", windows)))]
    let r: Result<(), String> = {
        let _ = ctx;
        Ok(())
    };
    if let Err(e) = r {
        die(&e)
    }
}

fn status(ctx: &Ctx) {
    let cfg = ctx.config();
    let rt = runtime();
    let url_host = match cfg.gateway {
        std::net::IpAddr::V6(v6) => format!("[{v6}]"),
        v4 => v4.to_string(),
    };
    match rt.block_on(probe::http_get(
        &url_host,
        cfg.status_port,
        "/.well-known/enclavedns",
    )) {
        Ok(body) => {
            let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            println!(
                "client      running, version {}, up {} s",
                v["version"].as_str().unwrap_or("?"),
                v["uptime_s"]
            );
            println!(
                "EnclaveDNS  {} ({})",
                v["upstream"].as_str().unwrap_or("?"),
                if v["upstream_reachable"].as_bool() == Some(true) {
                    "reachable"
                } else {
                    if v["strict"].as_bool() == Some(true) {
                        "UNREACHABLE: lookups fail (strict)"
                    } else {
                        "UNREACHABLE: using this machine's own DNS"
                    }
                }
            );
            if v["strict"].as_bool() == Some(true) {
                println!(
                    "fallback    none (strict): lookups fail while EnclaveDNS cannot be reached"
                );
            } else {
                let sys: Vec<&str> = v["system_dns"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                    .unwrap_or_default();
                println!(
                    "fallback    this machine's own DNS while EnclaveDNS cannot be reached ({})",
                    if sys.is_empty() {
                        "none found yet".to_string()
                    } else {
                        sys.join(", ")
                    }
                );
            }
            let q = &v["queries"];
            println!(
                "answers     {} from EnclaveDNS, {} from cache, {} from this machine's DNS, {} from DoH fallbacks, {} local-network, {} failed",
                q["enclavedns"], q["cached"], q["system"], q["fallback"], q["forwarded"], q["failed"]
            );
            if let Some(p) = v["gateway_problems"].as_array().filter(|p| !p.is_empty()) {
                for x in p {
                    println!(
                        "gateway     cannot listen on {} (.eth sites need it; DNS is fine)",
                        x.as_str().unwrap_or("?")
                    );
                }
            }
            if let Some(b) = v["backends"].as_object() {
                let s: Vec<String> = b
                    .iter()
                    .map(|(k, x)| {
                        format!(
                            "{k} {}",
                            if x["detected"].as_bool() == Some(true) {
                                "yes"
                            } else {
                                "no"
                            }
                        )
                    })
                    .collect();
                println!(".eth sites  {}", s.join(", "));
            }
        }
        Err(e) => println!("client      NOT RUNNING ({e})"),
    }
    #[cfg(target_os = "linux")]
    println!("this machine {}", linux::system_status());
    #[cfg(windows)]
    println!("this machine {}", windows::system_status());
}

fn query(ctx: &Ctx, rest: &[String]) {
    let Some(name) = rest.first() else { usage() };
    let qtype = rest.get(1).map(String::as_str).unwrap_or("A");
    let cfg = ctx.config();
    let server = cfg
        .dns_listen
        .first()
        .copied()
        .unwrap_or_else(|| "127.0.0.1:53".parse().unwrap());
    match runtime().block_on(probe::dns(server, name, qtype)) {
        Ok(lines) => {
            for l in lines {
                println!("{l}");
            }
        }
        Err(e) => die(&e),
    }
}

fn ca(ctx: &Ctx) {
    let p = ctx.state_dir.join(enclavedns_core::tls::CA_CERT);
    match std::fs::read_to_string(&p) {
        Ok(pem) => {
            eprintln!("{}", p.display());
            print!("{pem}");
        }
        Err(e) => die(&format!(
            "{}: {e} (the client makes its CA on first start)",
            p.display()
        )),
    }
}
