//! Windows: the service, and `enable`/`disable`.
//!
//! enable uses the Name Resolution Policy Table rather than each adapter's
//! DNS servers: one rule for "." sends every name to the client on every
//! adapter, present and future (the way WireGuard for Windows stops DNS
//! leaks), and a rule per connection-specific suffix (e.g. ".lan") keeps
//! names only the local network knows going to its own DNS servers. The
//! .eth CA goes into the machine's Root store, where Edge, Chrome and
//! Firefox (enterprise roots) find it; they honour its .eth/.ens name
//! constraint. disable removes exactly the rules and the certificate it added.

use crate::{probe, Ctx};
use std::ffi::OsString;
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

const NAME: &str = "EnclaveDNS";
const NRPT_COMMENT: &str = "EnclaveDNS";
const WATCHDOG_TASK: &str = "\\EnclaveDNS\\Watchdog";
const CA_CN: &str = "EnclaveDNS Local CA (this machine only, .eth and .ens names)";

fn powershell(script: &str) -> Result<String, String> {
    let o = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()
        .map_err(|e| format!("powershell: {e}"))?;
    if !o.status.success() {
        return Err(format!(
            "powershell: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&o.stdout).to_string())
}

fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let o = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("{cmd}: {e}"))?;
    if !o.status.success() {
        return Err(format!(
            "{cmd} {}: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&o.stdout).trim(),
            String::from_utf8_lossy(&o.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&o.stdout).to_string())
}

// ------------------------------------------------------------------ service

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let handler = move |c| match c {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(status) = service_control_handler::register(NAME, handler) else {
        return;
    };
    let set = |state, code| {
        let _ = status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        });
    };
    log_to_file();
    let ctx = Ctx {
        config_path: crate::paths::config_file(),
        state_dir: crate::paths::state_dir(),
    };
    let cfg = match enclavedns_core::Config::load(&ctx.config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("enclavedns: {e}");
            return set(ServiceState::Stopped, 1);
        }
    };
    let engine = match enclavedns_core::Engine::new(cfg, &ctx.state_dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("enclavedns: {e}");
            return set(ServiceState::Stopped, 2);
        }
    };
    set(ServiceState::Running, 0);
    let rt = crate::runtime();
    let failed = rt.block_on(async move {
        let mut serve = tokio::spawn(engine.run());
        let stop = tokio::task::spawn_blocking(move || stop_rx.recv());
        tokio::select! {
            r = &mut serve => {
                match &r {
                    Ok(Err(e)) => eprintln!("enclavedns: {e}"),
                    Err(e) => eprintln!("enclavedns: {e}"),
                    Ok(Ok(())) => {}
                }
                !matches!(r, Ok(Ok(())))
            }
            _ = stop => false,
        }
    });
    rt.shutdown_timeout(Duration::from_secs(2));
    // a failure exits non-zero so the service manager restarts it
    set(ServiceState::Stopped, if failed { 3 } else { 0 });
}

/// A service has no console: its stderr goes to %ProgramData%\EnclaveDNS\enclavedns.log
/// (kept under 1 MB).
fn log_to_file() {
    use std::os::windows::io::AsRawHandle;
    extern "system" {
        fn SetStdHandle(n: u32, h: *mut std::ffi::c_void) -> i32;
    }
    const STD_ERROR_HANDLE: u32 = -12i32 as u32;
    let p = crate::paths::program_data().join("enclavedns.log");
    if std::fs::metadata(&p).is_ok_and(|m| m.len() > 1 << 20) {
        let _ = std::fs::rename(&p, p.with_extension("log.old"));
    }
    if let Ok(f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&p)
    {
        // SAFETY: the handle stays valid for the life of the process (the file is leaked on purpose)
        unsafe { SetStdHandle(STD_ERROR_HANDLE, f.as_raw_handle()) };
        std::mem::forget(f);
        eprintln!("--- enclavedns {} service start", env!("CARGO_PKG_VERSION"));
    }
}

pub fn service(ctx: &Ctx, rest: &[String]) {
    let r = match rest.first().map(String::as_str) {
        Some("run") => service_dispatcher::start(NAME, ffi_service_main)
            .map_err(|e| format!("not started by the service manager: {e}")),
        Some("install") => install(ctx),
        Some("uninstall") => uninstall(),
        Some("start") => control(true),
        Some("stop") => control(false),
        _ => Err("usage: enclavedns service install|uninstall|start|stop".into()),
    };
    if let Err(e) = r {
        crate::die(&e)
    }
}

/// %ProgramData% lets ordinary users create files in new folders, so a user
/// could plant a config.toml that sends the machine's DNS elsewhere. The
/// EnclaveDNS folder is locked down: users may read it, only SYSTEM and
/// Administrators may change it, and the state folder (the CA's private
/// key) is closed to users entirely.
fn lock_down_state(ctx: &Ctx) -> Result<(), String> {
    const SYSTEM: &str = "*S-1-5-18:(OI)(CI)F";
    const ADMINS: &str = "*S-1-5-32-544:(OI)(CI)F";
    const USERS_READ: &str = "*S-1-5-32-545:(OI)(CI)RX";
    let base = crate::paths::program_data();
    std::fs::create_dir_all(&base).map_err(|e| e.to_string())?;
    let b = base.display().to_string();
    run(
        "icacls",
        &[
            &b,
            "/inheritance:r",
            "/grant:r",
            SYSTEM,
            "/grant:r",
            ADMINS,
            "/grant:r",
            USERS_READ,
        ],
    )?;
    // the config file the installer placed keeps no other grants than the folder's
    let cfg = ctx.config_path.display().to_string();
    if ctx.config_path.exists() {
        run("icacls", &[&cfg, "/reset"])?;
    }
    std::fs::create_dir_all(&ctx.state_dir).map_err(|e| e.to_string())?;
    let d = ctx.state_dir.display().to_string();
    run(
        "icacls",
        &[&d, "/inheritance:r", "/grant:r", SYSTEM, "/grant:r", ADMINS],
    )?;
    Ok(())
}

fn install(ctx: &Ctx) -> Result<(), String> {
    lock_down_state(ctx)?;
    let m = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| format!("open the service manager (run as administrator): {e}"))?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: "EnclaveDNS".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec!["service".into(), "run".into()],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let s = match m.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START) {
        Ok(s) => s,
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1073) => {
            // already installed: refresh its configuration
            let s = m
                .open_service(NAME, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
                .map_err(|e| e.to_string())?;
            s.change_config(&info).map_err(|e| e.to_string())?;
            s
        }
        Err(e) => return Err(format!("create the service: {e}")),
    };
    let _ =
        s.set_description("This computer's DNS through EnclaveDNS, and .eth sites in the browser");
    let restart = ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(2),
    };
    let _ = s.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(3600)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart.clone(), restart.clone(), restart]),
    });
    let _ = s.set_failure_actions_on_non_crash_failures(true);
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    run(
        "schtasks",
        &[
            "/Create",
            "/TN",
            WATCHDOG_TASK,
            "/TR",
            &format!("\"{}\" watchdog", exe.display()),
            "/SC",
            "MINUTE",
            "/MO",
            "1",
            "/RU",
            "SYSTEM",
            "/RL",
            "HIGHEST",
            "/F",
        ],
    )
    .map_err(|e| format!("the watchdog task: {e}"))?;
    println!("service {NAME} installed (starts with Windows), watchdog task {WATCHDOG_TASK} every minute");
    Ok(())
}

fn uninstall() -> Result<(), String> {
    let _ = run("schtasks", &["/Delete", "/TN", WATCHDOG_TASK, "/F"]);
    let m = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| e.to_string())?;
    let s = match m.open_service(
        NAME,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    ) {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };
    let _ = s.stop();
    for _ in 0..20 {
        if s.query_status()
            .map(|x| x.current_state == ServiceState::Stopped)
            .unwrap_or(true)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    s.delete().map_err(|e| e.to_string())?;
    println!("service {NAME} removed");
    Ok(())
}

fn control(start: bool) -> Result<(), String> {
    let m = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| e.to_string())?;
    let s = m
        .open_service(NAME, ServiceAccess::START | ServiceAccess::STOP)
        .map_err(|e| format!("{NAME}: {e}"))?;
    if start {
        s.start::<&str>(&[]).map_err(|e| e.to_string())?;
    } else {
        s.stop().map_err(|e| e.to_string())?;
    }
    Ok(())
}

// ------------------------------------------------------------ enable/disable

fn enabled_marker() -> std::path::PathBuf {
    crate::paths::program_data().join("enabled")
}

fn watchdog_state() -> std::path::PathBuf {
    crate::paths::program_data().join("watchdog-suspended")
}

/// The NRPT rules: one per connection-specific suffix to that network's own
/// DNS, and "." to the client. Replaces any earlier EnclaveDNS rules.
fn apply_nrpt(cfg: &enclavedns_core::Config) -> Result<String, String> {
    let servers: Vec<String> = cfg.dns_listen.iter().map(|a| a.ip().to_string()).collect();
    let script = format!(
        r#"$ErrorActionPreference = 'Stop'
Get-DnsClientNrptRule | Where-Object {{ $_.Comment -like '{c}*' }} | ForEach-Object {{ Remove-DnsClientNrptRule -Name $_.Name -Force }}
$seen = @{{}}
Get-DnsClient | Where-Object {{ $_.ConnectionSpecificSuffix }} | ForEach-Object {{
  $suffix = $_.ConnectionSpecificSuffix.Trim('.')
  $srv = (Get-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses |
    Where-Object {{ $_ -notlike '127.*' }}
  if ($srv -and -not $seen.ContainsKey($suffix)) {{
    $seen[$suffix] = 1
    Add-DnsClientNrptRule -Namespace ".$suffix" -NameServers $srv -Comment '{c} local network' | Out-Null
    Write-Output "   *.$suffix -> $($srv -join ', ')"
  }}
}}
Add-DnsClientNrptRule -Namespace '.' -NameServers @({s}) -Comment '{c}' | Out-Null
Clear-DnsClientCache
Write-Output '   every other name -> the client'"#,
        c = NRPT_COMMENT,
        s = servers
            .iter()
            .map(|s| format!("'{s}'"))
            .collect::<Vec<_>>()
            .join(",")
    );
    powershell(&script)
}

fn remove_nrpt() -> Result<(), String> {
    powershell(&format!(
        "Get-DnsClientNrptRule | Where-Object {{ $_.Comment -like '{NRPT_COMMENT}*' }} | ForEach-Object {{ Remove-DnsClientNrptRule -Name $_.Name -Force }}; Clear-DnsClientCache"
    ))
    .map(|_| ())
}

fn watchdog_log(msg: &str) {
    use std::io::Write;
    let p = crate::paths::program_data().join("watchdog.log");
    if std::fs::metadata(&p).is_ok_and(|m| m.len() > 256 << 10) {
        let _ = std::fs::rename(&p, p.with_extension("log.old"));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&p)
    {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(f, "{t} {msg}");
    }
    println!("{msg}");
}

/// `enclavedns watchdog`, every minute as SYSTEM (the \EnclaveDNS\Watchdog
/// task): this PC's DNS must never depend on a dead client. When the client
/// stops answering, restart it (killing it if it hangs); if it still does
/// not answer, remove the NRPT rules so DNS fails open to the network's own
/// servers; put them back once it answers again.
pub fn watchdog(ctx: &Ctx) -> Result<(), String> {
    if !enabled_marker().exists() {
        return Ok(());
    }
    let cfg = ctx.config();
    let dns = cfg
        .dns_listen
        .first()
        .copied()
        .ok_or("dns_listen is empty")?;
    let suspended = watchdog_state().exists();
    if !probe::alive(dns, 3) {
        watchdog_log(&format!(
            "the client does not answer on {dns}: restarting the {NAME} service"
        ));
        let _ = control(false);
        std::thread::sleep(Duration::from_secs(3));
        // a hung process ignores the stop: end it
        let _ = run("taskkill", &["/F", "/FI", &format!("SERVICES eq {NAME}")]);
        let _ = control(true);
        let mut back = false;
        for _ in 0..10 {
            std::thread::sleep(Duration::from_secs(2));
            if probe::alive(dns, 1) {
                back = true;
                break;
            }
        }
        if !back {
            if !suspended {
                remove_nrpt()?;
                std::fs::write(
                    watchdog_state(),
                    "the client did not answer; NRPT rules removed (DNS fails open)\n",
                )
                .map_err(|e| e.to_string())?;
                watchdog_log("still no answer: NRPT rules removed, this PC uses the network's DNS until the client answers again");
            }
            return Ok(());
        }
        watchdog_log("the client answers again after a restart");
    }
    if suspended {
        apply_nrpt(&cfg)?;
        let _ = std::fs::remove_file(watchdog_state());
        watchdog_log("the client answers: NRPT rules restored");
    }
    Ok(())
}

fn wait_answering(server: std::net::SocketAddr) -> bool {
    let rt = crate::runtime();
    for _ in 0..30 {
        if rt
            .block_on(probe::dns(server, "enclave.host", "A"))
            .is_ok_and(|l| l.first().is_some_and(|h| h.contains("NoError")))
        {
            return true;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    false
}

pub fn enable(ctx: &Ctx) -> Result<(), String> {
    let cfg = ctx.config();
    let dns = cfg
        .dns_listen
        .first()
        .copied()
        .ok_or("dns_listen is empty")?;
    println!("== 1/3 the client answers on {dns}");
    if !wait_answering(dns) {
        return Err(format!(
            "nothing answers on {dns}; start the service: enclavedns service start"
        ));
    }
    println!("== 2/3 trust the .eth CA");
    let ca = ctx.state_dir.join(enclavedns_core::tls::CA_CERT);
    if ca.exists() {
        run(
            "certutil",
            &["-addstore", "-f", "Root", &ca.display().to_string()],
        )?;
        println!("   in the machine's Root store; restart your browser to load it");
    } else {
        println!(
            "   skipped: {} does not exist yet (HTTPS for .eth stays off)",
            ca.display()
        );
    }
    println!("== 3/3 send this computer's DNS to the client (NRPT)");
    print!("{}", apply_nrpt(&cfg)?);
    std::fs::write(enabled_marker(), "enabled by `enclavedns enable`; the watchdog keeps the NRPT rules only while the client answers\n")
        .map_err(|e| e.to_string())?;
    match powershell("(Resolve-DnsName -Name enclave.host -Type A -DnsOnly -QuickTimeout | Select-Object -First 1).IPAddress") {
        Ok(ip) if !ip.trim().is_empty() => println!("DONE: this computer resolves through EnclaveDNS (enclave.host -> {})", ip.trim()),
        _ => println!("WARNING: enclave.host did not resolve through the system; check `enclavedns status`"),
    }
    Ok(())
}

pub fn disable(_ctx: &Ctx) -> Result<(), String> {
    let _ = std::fs::remove_file(enabled_marker());
    let _ = std::fs::remove_file(watchdog_state());
    remove_nrpt()?;
    println!("DNS policy rules removed");
    match run("certutil", &["-delstore", "Root", CA_CN]) {
        Ok(_) => println!("CA no longer trusted"),
        Err(_) => println!("(the CA was not in the Root store)"),
    }
    println!("DONE: DNS is back to the network's own");
    Ok(())
}

pub fn system_status() -> String {
    if watchdog_state().exists() {
        return "uses the NETWORK's DNS for now: the watchdog removed the NRPT rules because the client stopped answering (see watchdog.log)".into();
    }
    match powershell(&format!(
        "@(Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{NRPT_COMMENT}' }}).Count"
    )) {
        Ok(n) if n.trim() != "0" && !n.trim().is_empty() => {
            "uses the client (NRPT rule for \".\")".into()
        }
        Ok(_) => "does NOT use the client yet (enclavedns enable, as administrator)".into(),
        Err(e) => format!("unknown ({e})"),
    }
}
