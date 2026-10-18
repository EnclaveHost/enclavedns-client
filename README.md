# EnclaveDNS client

Your device's DNS through [EnclaveDNS](https://github.com/EnclaveHost/enclave-apps/tree/main/enclavedns),
and `.eth` sites in an ordinary browser. For Linux, Windows and Android.

EnclaveDNS is a validating DNSSEC resolver that runs in an attested enclave
on [enclave.host](https://enclave.host): it checks every answer's signatures
from the DNS root down before handing it out, keeps no query logs, and resolves
ENS (`.eth`) names natively. This client makes a device use it:

- **All DNS goes to EnclaveDNS** over DNS-over-HTTPS, through a local cache.
  If EnclaveDNS cannot be reached, lookups go to the device's own DNS (the
  servers its network provides) until it can. An answer from EnclaveDNS is
  final, SERVFAIL included, which is how a DNSSEC failure looks, so a forged
  answer is never "rescued" by the fallback. Set `strict = true` to use
  EnclaveDNS only: lookups then fail while it cannot be reached.
- **`.eth` sites open in the browser.** Most ENS names point at content (an
  IPFS or Swarm hash, an Arweave transaction, a Tor onion service), not an
  IP address. The client answers those names with a local gateway address and
  serves the site from **software on your own machine**: kubo (IPFS/IPNS),
  Bee (Swarm), an AR.IO gateway (Arweave) or Tor. It never falls back to a
  public gateway. When the software is missing, the browser gets a page that
  says which and how to start it, instead of "This site can't be reached".
  A `url` text record redirects, and a name with only a wallet address gets
  a page showing what it holds. Names with real DNS records stored on-chain
  keep them.
- **HTTPS for `.eth`.** No public CA can issue a certificate for an ENS name,
  so the client makes its own on first start, and signs a certificate per name
  on demand. The CA carries an X.509 name constraint (`DNS:eth`, `DNS:ens`):
  browsers reject anything it signs for any other name, even if its key
  leaked. The key never leaves the client's state directory, readable by
  the service alone. Many dapps require HTTPS, and Web Crypto, service
  workers and wallets need a secure context.
- **Local names keep working.** Names only your network knows (`*.lan`, a
  router's own zone) go to the network's own DNS servers.
- Firefox is told to keep its own DNS-over-HTTPS off (`use-application-dns.net`),
  so it uses the system resolver too.
- **DNS never depends on a dead client.** A watchdog (a systemd timer on Linux,
  a SYSTEM scheduled task on Windows) checks every minute that the client
  answers. If it does not, it restarts it; if it still does not, it gives DNS
  back to the network's own servers until the client answers again (with
  `strict = true` it only restarts it).

## Install

### Arch Linux (AUR)

```sh
yay -S enclavedns            # or: git clone https://aur.archlinux.org/enclavedns.git && cd enclavedns && makepkg -si
sudo systemctl enable --now enclavedns
sudo enclavedns enable       # this machine's DNS + the .eth CA for HTTPS
enclavedns status
```

Restart your browser afterwards so it loads the CA. `sudo enclavedns disable`
puts DNS and trust back exactly as they were; removing the package does that
too.

### Other Linux

Download `enclavedns-<version>-linux-<arch>.tar.gz` from the
[releases](https://github.com/EnclaveHost/enclavedns-client/releases), then:

```sh
sudo install -m755 enclavedns /usr/bin/enclavedns
sudo install -m644 enclavedns.service enclavedns-watchdog.service enclavedns-watchdog.timer /etc/systemd/system/
sudo install -m644 enclavedns.sysusers /usr/lib/sysusers.d/enclavedns.conf && sudo systemd-sysusers
sudo install -Dm644 config.toml /etc/enclavedns/config.toml
sudo systemctl enable --now enclavedns
sudo enclavedns enable
```

`enable` handles NetworkManager, systemd-resolved and a plain
`/etc/resolv.conf`, and trusts the CA with `update-ca-trust` (Arch, Fedora)
or `update-ca-certificates` (Debian, Ubuntu). Chrome and Chromium on Linux
ignore the system store for local CAs and read only the user's NSS database,
so `enable` also adds it to `~/.pki/nssdb` of the user who ran `sudo` (needs
`certutil`: `nss` on Arch, `libnss3-tools` on Debian/Ubuntu). Other users:
`certutil -d sql:$HOME/.pki/nssdb -A -t C,, -n "EnclaveDNS Local CA" -i /var/lib/enclavedns/ca.crt`.

### Windows

Run `EnclaveDNS-Setup-<version>-x64.exe` from the
[releases](https://github.com/EnclaveHost/enclavedns-client/releases). It
installs the EnclaveDNS service and, with the box ticked, points the
computer's DNS at it and trusts the `.eth` CA. Uninstalling undoes both.

The DNS change is one Name Resolution Policy Table rule for `.`, covering
every adapter, present and future, plus a rule per connection-specific
suffix that keeps local names on the local network. From an administrator
prompt: `enclavedns status`, `enclavedns disable`, `enclavedns enable`.

The installer is not code-signed yet, so SmartScreen will ask before
running it ("More info", then "Run anyway").

### Android

Install `EnclaveDNS-<version>.apk` from the
[releases](https://github.com/EnclaveHost/enclavedns-client/releases) and
turn it on. It is a **DNS-only VPN**: it routes just two private addresses
into the app (the DNS server it gives Android, and the `.eth` gateway), so
all other traffic takes the normal network.

- For HTTPS on `.eth`, tap *Save the .eth certificate*, then install it in
  Android's settings (Security → Encryption & credentials → Install a
  certificate → CA certificate). Chrome trusts user-installed CAs; some
  apps do not.
- Android's **Private DNS** set to a hostname sends DNS around any VPN. Set
  it to *Off* or *Automatic*; the app warns when it is not.
- To keep it on across reboots, enable *Always-on VPN* for EnclaveDNS in
  Android's VPN settings.
- A phone rarely runs IPFS or Swarm itself: point the backend settings at
  nodes elsewhere on your network, and use Orbot for Tor.

## Configuration

`/etc/enclavedns/config.toml` (Linux), `%ProgramData%\EnclaveDNS\config.toml`
(Windows), the settings screen (Android). Every key is optional:

```toml
upstream = "https://59f1273d.app.enclave.host"   # EnclaveDNS
strict = false                                   # true: EnclaveDNS only, lookups fail when it is unreachable
system_dns = []                                  # the fallback: this device's own DNS, found by itself when empty
fallback = []                                    # extra DoH resolvers after it, e.g. "https://dns.quad9.net/dns-query"
bootstrap = ["9.9.9.9:53", "149.112.112.112:53", "1.1.1.1:53"]  # finds the upstreams' own addresses
dns_listen = ["127.0.0.1:53", "[::1]:53"]
gateway = "127.0.0.3"                            # where .eth sites are served
https = true
redirect_https = true

[[forward]]                                      # names only the local network knows
zone = "lan"
servers = ["192.168.1.1:53"]

[backends]                                       # local software for .eth sites
ipfs = "http://127.0.0.1:8080"                   # kubo gateway
ipfs_api = "http://127.0.0.1:5001"               # kubo API, to resolve IPNS quickly
bee = "http://127.0.0.1:1633"                    # Swarm
arweave = "http://127.0.0.1:3000"                # AR.IO
tor = ["127.0.0.1:9050", "127.0.0.1:9150"]       # tor, Tor Browser
```

On Linux, `enclavedns enable` writes the network's search domains as
`[[forward]]` zones and your kubo's addresses (from `~/.ipfs/config`) in a
managed block at the end of the file.

## Trust

- **What EnclaveDNS sees:** every name this device looks up (like any
  resolver). It runs in an attested enclave and keeps counters, not query
  logs; that is the point of using it. ENS answers come from several Ethereum
  providers at once and are accepted only when they agree.
- **What the fallback sees:** your network's DNS (usually your router or ISP)
  sees names looked up while EnclaveDNS is unreachable, in plain DNS. Set
  `strict = true` to fail closed instead.
- **The bootstrap servers** see the upstreams' own host names, and nothing
  else.
- **The local CA** can only vouch for `.eth` and `.ens` names (an X.509 name
  constraint, enforced by browsers and TLS libraries; tested in CI against a
  certificate forged with its own key).

## Build

```sh
cargo build --release -p enclavedns          # Linux/Windows CLI and service
cargo test --workspace
cd android && ./gradlew assembleDebug        # needs JDK 17-21, the Android SDK + NDK 28, cargo-ndk
```

Layout:

```
crates/core      the engine: stub resolver, cache, DoH upstreams, .eth gateway, CA
crates/cli       enclavedns: run, status, query, enable/disable, Windows service
android/rust     the engine behind the Android VPN (JNI, user-space TCP/IP stack)
android/app      the Android app (Kotlin, no AndroidX)
packaging/       systemd unit, AUR PKGBUILD, Windows installer
```

## License

[Enclave Source-Available License v1.0](LICENSE).
