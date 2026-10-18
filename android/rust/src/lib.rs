//! The EnclaveDNS client engine for Android, behind a DNS-only VPN.
//!
//! Android apps cannot listen on ports 53, 80 or 443, so the app's VPN
//! routes only two addresses into this library: the DNS server it hands
//! the system (10.53.0.1 / fd53::1) and the `.eth` gateway (10.53.0.3).
//! A user-space TCP/IP stack (ipstack) turns the VPN's packets into UDP
//! and TCP streams; DNS goes to the engine's stub resolver, ports 80 and 443
//! to its gateway. Nothing else is routed into the VPN, so all other
//! traffic is untouched.

use enclavedns_core::{Config, Engine};
use ipstack::{IpStack, IpStackConfig, IpStackStream};
use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};
use jni::JNIEnv;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const DNS_V4: Ipv4Addr = Ipv4Addr::new(10, 53, 0, 1);
pub const DNS_V6: Ipv6Addr = Ipv6Addr::new(0xfd53, 0, 0, 0, 0, 0, 0, 1);
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 53, 0, 3);
const MTU: u16 = 1500;

struct Running {
    rt: tokio::runtime::Runtime,
    engine: Arc<Engine>,
    stop: tokio::sync::watch::Sender<bool>,
}

static RUNNING: Mutex<Option<Running>> = Mutex::new(None);

/// The Android config: the user's settings, with the addresses this
/// library serves on.
pub fn android_config(toml_text: &str) -> Result<Config, String> {
    let mut cfg = Config::from_toml(toml_text)?;
    cfg.dns_listen = Vec::new();
    cfg.gateway = IpAddr::V4(GATEWAY);
    Ok(cfg)
}

fn is_dns(a: SocketAddr) -> bool {
    a.port() == 53 && (a.ip() == IpAddr::V4(DNS_V4) || a.ip() == IpAddr::V6(DNS_V6))
}

/// Serve every stream the VPN's packets make, until `stop` turns true.
pub async fn serve_device<D>(
    engine: Arc<Engine>,
    device: D,
    mut stop: tokio::sync::watch::Receiver<bool>,
) where
    D: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut c = IpStackConfig::default();
    c.mtu_unchecked(MTU);
    let mut stack = IpStack::new(c, device);
    let tls = engine.tls.clone().map(tokio_rustls_acceptor);
    loop {
        let s = tokio::select! {
            s = stack.accept() => s,
            _ = stop.changed() => return,
        };
        let Ok(s) = s else { return };
        let dst = s.peer_addr();
        let e = engine.clone();
        match s {
            IpStackStream::Udp(mut udp) if is_dns(dst) => {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    // one datagram per read; the stream ends when the flow idles out
                    while let Ok(n) = udp.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if let Some(r) = e.answer_udp(&buf[..n]).await {
                            if udp.write_all(&r).await.is_err() {
                                break;
                            }
                        }
                    }
                });
            }
            IpStackStream::Tcp(tcp) if is_dns(dst) => {
                tokio::spawn(enclavedns_core::dns::serve_tcp_stream(tcp, e));
            }
            IpStackStream::Tcp(tcp) if dst.ip() == IpAddr::V4(GATEWAY) && dst.port() == 80 => {
                tokio::spawn(enclavedns_core::gateway::serve_io(tcp, e, None));
            }
            IpStackStream::Tcp(tcp) if dst.ip() == IpAddr::V4(GATEWAY) && dst.port() == 443 => {
                if let Some(acc) = tls.clone() {
                    tokio::spawn(enclavedns_core::gateway::serve_io(tcp, e, Some(acc)));
                }
            }
            // anything else (DNS-over-TLS probes on 853, stray packets): dropped
            _ => {}
        }
    }
}

fn tokio_rustls_acceptor(c: Arc<rustls_cfg::ServerConfig>) -> tokio_rustls_reexport::TlsAcceptor {
    tokio_rustls_reexport::TlsAcceptor::from(c)
}

// the core's TLS types, under names that do not collide with anything here
use enclavedns_core::tls::rustls as rustls_cfg;
use enclavedns_core::tls::tokio_rustls as tokio_rustls_reexport;

/// Start the engine on the VPN's file descriptor (this library owns it from
/// here and closes it on stop).
pub fn start(fd: i32, config_toml: &str, state_dir: &str) -> Result<(), String> {
    stop();
    let cfg = android_config(config_toml)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let engine = Engine::new(cfg, std::path::Path::new(state_dir))?;
    let mut tc = tun::Configuration::default();
    tc.raw_fd(fd).close_fd_on_drop(true);
    let device = {
        let _g = rt.enter();
        tun::create_as_async(&tc).map_err(|e| format!("the VPN interface: {e}"))?
    };
    let (tx, rx) = tokio::sync::watch::channel(false);
    rt.spawn(serve_device(engine.clone(), device, rx));
    *RUNNING.lock().unwrap() = Some(Running {
        rt,
        engine,
        stop: tx,
    });
    Ok(())
}

pub fn stop() {
    if let Some(r) = RUNNING.lock().unwrap().take() {
        let _ = r.stop.send(true);
        r.rt.shutdown_timeout(std::time::Duration::from_secs(2));
    }
}

pub fn status() -> String {
    let g = RUNNING.lock().unwrap();
    match g.as_ref() {
        Some(r) => {
            let e = r.engine.clone();
            r.rt.block_on(async move { e.status().await }).to_string()
        }
        None => serde_json::json!({"running": false}).to_string(),
    }
}

// --------------------------------------------------------------------- JNI

fn jstr(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s).map(|s| s.into()).unwrap_or_default()
}

fn out(env: &mut JNIEnv, s: Option<String>) -> jstring {
    match s {
        Some(s) => env
            .new_string(s)
            .map(|j| j.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }
}

/// `Native.start(fd, configToml, stateDir)`: null on success, else the error.
#[no_mangle]
pub extern "system" fn Java_host_enclave_dns_Native_start<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
    fd: jint,
    config: JString<'l>,
    state_dir: JString<'l>,
) -> jstring {
    let (config, state_dir) = (jstr(&mut env, &config), jstr(&mut env, &state_dir));
    let r = start(fd, &config, &state_dir).err();
    out(&mut env, r)
}

#[no_mangle]
pub extern "system" fn Java_host_enclave_dns_Native_stop<'l>(_env: JNIEnv<'l>, _c: JClass<'l>) {
    stop();
}

#[no_mangle]
pub extern "system" fn Java_host_enclave_dns_Native_status<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
) -> jstring {
    let s = status();
    out(&mut env, Some(s))
}

/// `Native.check(configToml)`: null when the settings are valid, else why not.
#[no_mangle]
pub extern "system" fn Java_host_enclave_dns_Native_check<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
    config: JString<'l>,
) -> jstring {
    let config = jstr(&mut env, &config);
    let r = android_config(&config).err();
    out(&mut env, r)
}

/// `Native.caPem(stateDir)`: the .eth CA certificate (made if missing).
#[no_mangle]
pub extern "system" fn Java_host_enclave_dns_Native_caPem<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
    state_dir: JString<'l>,
) -> jstring {
    let dir = jstr(&mut env, &state_dir);
    let p = std::path::Path::new(&dir);
    let r = enclavedns_core::tls::Ca::load_or_create(p)
        .ok()
        .and_then(|_| std::fs::read_to_string(p.join(enclavedns_core::tls::CA_CERT)).ok());
    out(&mut env, r)
}
