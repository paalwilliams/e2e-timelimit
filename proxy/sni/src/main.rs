//! leechproxy-sni: transparent / explicit proxy that blocks and time-limits sites
//! by hostname (TLS SNI or HTTP Host), per person, without decrypting anything.
//! Policy decisions come from the LeechProxy Python helper; this binary only
//! moves bytes, measures activity, and cuts connections when told to.

mod blockpage;
mod helper;
mod net;
mod parse;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use helper::{Decision, Helper};
use parse::Peek;

const MAX_PEEK: usize = 16 * 1024 + 5;
const TLS_ALERT_ACCESS_DENIED: &[u8] = b"\x15\x03\x01\x00\x02\x02\x31";

struct Config {
    block_page: Option<String>,
    active_bytes: u64,
    recheck: Duration,
    quiet: bool,
}

struct ConnState {
    host: String,
    ip: String,
    mac: Option<String>,
    dst: String,
    bytes: AtomicU64,
    cancel: watch::Sender<bool>,
}

struct App {
    cfg: Config,
    /// Local CA for HTTPS block pages (None = just reset blocked TLS connections)
    tls: Option<blockpage::BlockTls>,
    helper: Helper,
    arp: net::Arp,
    conns: Mutex<HashMap<u64, Arc<ConnState>>>,
    next_id: AtomicU64,
}

impl App {
    fn log(&self, msg: std::fmt::Arguments) {
        if !self.cfg.quiet {
            println!("{msg}");
        }
    }

    async fn decide(&self, ip: &str, mac: Option<&str>, host: &str, dst: &str, count: bool) -> Decision {
        self.helper.ask(ip, mac, host, dst, count).await
    }

    fn blocked_http(&self, host: &str, d: &Decision) -> Vec<u8> {
        match &self.cfg.block_page {
            Some(page) => format!(
                "HTTP/1.1 302 Found\r\nLocation: {page}?host={}&msg={}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                helper::enc(host),
                helper::enc(&d.message)
            )
            .into_bytes(),
            None => {
                let body = format!("<h1>Blocked</h1><p>{host} is blocked by LeechProxy: {}</p>", html(&d.message));
                format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .into_bytes()
            }
        }
    }

    /// Connect upstream and copy bytes both ways until either side closes or we're cancelled.
    async fn splice(self: &Arc<Self>, client: TcpStream, upstream: String, host: String, ip: String,
                    mac: Option<String>, first: Vec<u8>) {
        let up = match tokio::time::timeout(Duration::from_secs(15), TcpStream::connect(&upstream)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return self.log(format_args!("upstream {upstream} ({host}): {e}")),
            Err(_) => return self.log(format_args!("upstream {upstream} ({host}): timeout")),
        };
        let _ = up.set_nodelay(true);
        let _ = client.set_nodelay(true);
        let (cancel, cancel_rx) = watch::channel(false);
        let st = Arc::new(ConnState { host, ip, mac, dst: upstream, bytes: AtomicU64::new(0), cancel });
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.conns.lock().unwrap().insert(id, st.clone());

        let (cr, cw) = client.into_split();
        let (ur, mut uw) = up.into_split();
        if !first.is_empty() && uw.write_all(&first).await.is_err() {
            self.conns.lock().unwrap().remove(&id);
            return;
        }
        tokio::join!(pump(cr, uw, &st, cancel_rx.clone()), pump(ur, cw, &st, cancel_rx));

        self.conns.lock().unwrap().remove(&id);
        // Count the tail of short connections that ended between rechecks.
        if st.bytes.load(Ordering::Relaxed) >= self.cfg.active_bytes && !*st.cancel.borrow() {
            let app = self.clone();
            tokio::spawn(async move {
                app.decide(&st.ip, st.mac.as_deref(), &st.host, &st.dst, true).await;
            });
        }
    }

    async fn handle_transparent(self: Arc<Self>, mut client: TcpStream, peer: SocketAddr) {
        let Some(dst) = net::original_dst(&client) else { return };
        if client.local_addr().map_or(true, |l| l == dst) {
            return; // connected to the proxy port directly, not redirected
        }
        let ip = canon_ip(peer);
        let mac = self.arp.lookup(&ip);
        let is_http = dst.port() == 80;

        let mut buf = Vec::with_capacity(4096);
        let host = loop {
            let mut chunk = [0u8; 4096];
            let n = match tokio::time::timeout(Duration::from_secs(10), client.read(&mut chunk)).await {
                Ok(Ok(n)) if n > 0 => n,
                _ => return,
            };
            buf.extend_from_slice(&chunk[..n]);
            let parsed = if is_http {
                match parse::http_host(&buf) {
                    Peek::Done((h, _)) => Peek::Done(h),
                    Peek::More => Peek::More,
                    Peek::Invalid => Peek::Invalid,
                }
            } else {
                parse::sni(&buf)
            };
            match parsed {
                Peek::Done(h) => break h,
                Peek::Invalid => break None,
                Peek::More if buf.len() >= MAX_PEEK => break None,
                Peek::More => continue,
            }
        };

        if let Some(h) = &host {
            let d = self.decide(&ip, mac.as_deref(), h, &dst.ip().to_string(), false).await;
            if d.blocked {
                self.log(format_args!("BLOCK {ip} {} {h} {}", mac.as_deref().unwrap_or("-"), d.message));
                if is_http {
                    let _ = client.write_all(&self.blocked_http(h, &d)).await;
                } else if let Some(tls) = &self.tls {
                    let resp = self.blocked_http(h, &d);
                    if let Err(e) = tls.serve(blockpage::Prefixed::new(buf, client), h, &resp).await {
                        self.log(format_args!("block page for {h} not shown: {e}"));
                    }
                    return;
                } else {
                    let _ = client.write_all(TLS_ALERT_ACCESS_DENIED).await;
                }
                let _ = client.shutdown().await;
                return;
            }
        }
        self.splice(client, dst.to_string(), host.unwrap_or_default(), ip, mac, buf).await;
    }

    async fn handle_explicit(self: Arc<Self>, mut client: TcpStream, peer: SocketAddr) {
        let ip = canon_ip(peer);
        let mac = self.arp.lookup(&ip);
        let mut buf = Vec::with_capacity(2048);
        let head_end = loop {
            let mut chunk = [0u8; 4096];
            let n = match tokio::time::timeout(Duration::from_secs(15), client.read(&mut chunk)).await {
                Ok(Ok(n)) if n > 0 => n,
                _ => return,
            };
            buf.extend_from_slice(&chunk[..n]);
            if let Some(e) = parse::find(&buf, b"\r\n\r\n") {
                break e + 4;
            }
            if buf.len() > MAX_PEEK {
                return;
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        let rest = buf[head_end..].to_vec();
        let mut lines = head.split("\r\n");
        let req = lines.next().unwrap_or("");
        let mut parts = req.splitn(3, ' ');
        let (method, target, version) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""), parts.next().unwrap_or("HTTP/1.1"));

        if method.eq_ignore_ascii_case("CONNECT") {
            let host = parse::strip_port(target).to_ascii_lowercase();
            let port = target.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()).unwrap_or(443);
            let d = self.decide(&ip, mac.as_deref(), &host, "-", false).await;
            if d.blocked {
                self.log(format_args!("BLOCK {ip} {host} {}", d.message));
                if let (Some(tls), 443) = (&self.tls, port) {
                    // Browsers ignore proxy error pages for CONNECT, so accept the tunnel
                    // and answer inside it with our own TLS session + redirect.
                    if client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.is_ok() {
                        let resp = self.blocked_http(&host, &d);
                        if let Err(e) = tls.serve(blockpage::Prefixed::new(rest, client), &host, &resp).await {
                            self.log(format_args!("block page for {host} not shown: {e}"));
                        }
                    }
                    return;
                }
                let body = format!("Blocked by LeechProxy: {}", d.message);
                let resp = format!("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                let _ = client.write_all(resp.as_bytes()).await;
                return;
            }
            if client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.is_err() {
                return;
            }
            let upstream = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
            return self.splice(client, upstream, host, ip, mac, rest).await;
        }

        // Absolute-form plain HTTP: "GET http://host[:port]/path HTTP/1.1"
        let Some(after) = target.strip_prefix("http://") else {
            let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
            return;
        };
        let (authority, path) = match after.find('/') {
            Some(i) => (&after[..i], &after[i..]),
            None => (after, "/"),
        };
        let host = parse::strip_port(authority).to_ascii_lowercase();
        let port = authority.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()).unwrap_or(80);
        let d = self.decide(&ip, mac.as_deref(), &host, "-", false).await;
        if d.blocked {
            self.log(format_args!("BLOCK {ip} {host} {}", d.message));
            let _ = client.write_all(&self.blocked_http(&host, &d)).await;
            return;
        }
        // One request per connection keeps this mode simple and correct.
        let mut out = format!("{method} {path} {version}\r\nConnection: close\r\n");
        for h in lines.filter(|l| !l.is_empty()) {
            let lower = h.to_ascii_lowercase();
            if !lower.starts_with("proxy-connection:") && !lower.starts_with("connection:") {
                out.push_str(h);
                out.push_str("\r\n");
            }
        }
        out.push_str("\r\n");
        let mut first = out.into_bytes();
        first.extend_from_slice(&rest);
        self.splice(client, format!("{host}:{port}"), host, ip, mac, first).await;
    }

    /// Every `recheck`: charge a minute to connections that moved data, and cut blocked ones.
    async fn monitor(self: Arc<Self>) {
        let mut tick = tokio::time::interval(self.cfg.recheck);
        tick.tick().await;
        loop {
            tick.tick().await;
            let snapshot: Vec<Arc<ConnState>> = self.conns.lock().unwrap().values().cloned().collect();
            // Ask once per (client, host) per tick, not once per connection.
            let mut seen: HashMap<(String, String), (bool, Decision)> = HashMap::new();
            for c in &snapshot {
                let active = c.bytes.swap(0, Ordering::Relaxed) >= self.cfg.active_bytes;
                if c.host.is_empty() {
                    continue;
                }
                let key = (c.ip.clone(), c.host.clone());
                let need = match seen.get(&key) {
                    None => true,
                    Some((counted, _)) => active && !counted,
                };
                if need {
                    let d = self.decide(&c.ip, c.mac.as_deref(), &c.host, &c.dst, active).await;
                    let counted = active || seen.get(&key).map_or(false, |s| s.0);
                    seen.insert(key.clone(), (counted, d));
                }
                if seen[&key].1.blocked {
                    self.log(format_args!("CUT {} {} {}", c.ip, c.host, seen[&key].1.message));
                    let _ = c.cancel.send(true);
                }
            }
        }
    }
}

async fn pump(mut r: OwnedReadHalf, mut w: OwnedWriteHalf, st: &ConnState, mut cancel: watch::Receiver<bool>) {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        tokio::select! {
            biased;
            _ = cancel.changed() => break,
            res = r.read(&mut buf) => match res {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    st.bytes.fetch_add(n as u64, Ordering::Relaxed);
                    if w.write_all(&buf[..n]).await.is_err() { break; }
                }
            }
        }
    }
    let _ = w.shutdown().await;
}

fn canon_ip(a: SocketAddr) -> String {
    match a.ip() {
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(|v4| v4.to_string()).unwrap_or_else(|| v6.to_string()),
        ip => ip.to_string(),
    }
}

fn html(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

const USAGE: &str = "\
leechproxy-sni [options]
  --transparent ADDR:PORT   listener for firewall-redirected traffic (Linux; 80 and 443 can share it)
  --explicit ADDR:PORT      ordinary HTTP proxy listener (CONNECT), e.g. 127.0.0.1:3128
  --helper CMD              policy helper command (default: \"python3 -m leechproxy.acl_helper\")
  --block-page URL          redirect blocked plain-HTTP requests here, e.g. http://192.168.1.1:8080/blocked
  --active-bytes N          bytes per recheck interval for a connection to count as active (default 2048)
  --recheck SECS            seconds between live-connection checks (default 15)
  --ca-dir DIR              local CA for HTTPS block pages (default: $LEECHPROXY_DATA/ca)
  --no-block-page-tls       don't show block pages for HTTPS; just reset blocked connections
  --quiet                   don't log blocks/cuts
Environment (passed to the helper): LEECHPROXY_DATA, PYTHONPATH";

#[tokio::main]
async fn main() {
    let mut transparent = vec![];
    let mut explicit = vec![];
    let mut helper_cmd = "python3 -m leechproxy.acl_helper".to_string();
    let mut cfg = Config { block_page: None, active_bytes: 2048, recheck: Duration::from_secs(15), quiet: false };
    let mut ca_dir = std::env::var("LEECHPROXY_DATA").map(|d| format!("{d}/ca")).unwrap_or_else(|_| "ca".into());
    let mut block_tls = true;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || args.next().unwrap_or_else(|| { eprintln!("{a} needs a value\n\n{USAGE}"); std::process::exit(2) });
        match a.as_str() {
            "--transparent" => transparent.push(val()),
            "--explicit" => explicit.push(val()),
            "--helper" => helper_cmd = val(),
            "--block-page" => cfg.block_page = Some(val()),
            "--active-bytes" => cfg.active_bytes = val().parse().expect("--active-bytes: number"),
            "--recheck" => cfg.recheck = Duration::from_secs(val().parse().expect("--recheck: seconds")),
            "--quiet" => cfg.quiet = true,
            "--ca-dir" => ca_dir = val(),
            "--no-block-page-tls" => block_tls = false,
            "-h" | "--help" => { println!("{USAGE}"); return; }
            _ => { eprintln!("unknown option {a}\n\n{USAGE}"); std::process::exit(2) }
        }
    }
    if transparent.is_empty() && explicit.is_empty() {
        eprintln!("{USAGE}");
        std::process::exit(2);
    }
    if !transparent.is_empty() && !cfg!(target_os = "linux") {
        eprintln!("warning: --transparent needs Linux (netfilter REDIRECT); use --explicit on this OS");
    }

    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let tls = if block_tls {
        match blockpage::BlockTls::load_or_create(std::path::Path::new(&ca_dir)) {
            Ok(t) => Some(t),
            Err(e) => {
                eprintln!("HTTPS block pages disabled: {e}");
                None
            }
        }
    } else {
        None
    };

    let app = Arc::new(App {
        cfg,
        tls,
        helper: Helper::new(helper_cmd.split_whitespace().map(String::from).collect()),
        arp: net::Arp::new(),
        conns: Mutex::new(HashMap::new()),
        next_id: AtomicU64::new(1),
    });

    for (addrs, transparent_mode) in [(transparent, true), (explicit, false)] {
        for addr in addrs {
            let listener = TcpListener::bind(&addr).await.unwrap_or_else(|e| {
                eprintln!("cannot listen on {addr}: {e}");
                std::process::exit(1)
            });
            println!("{} listener on {addr}", if transparent_mode { "transparent" } else { "explicit proxy" });
            let app = app.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((sock, peer)) = listener.accept().await else { continue };
                    let app = app.clone();
                    tokio::spawn(async move {
                        if transparent_mode { app.handle_transparent(sock, peer).await } else { app.handle_explicit(sock, peer).await }
                    });
                }
            });
        }
    }
    tokio::spawn(app.clone().monitor());
    let _ = tokio::signal::ctrl_c().await;
}
