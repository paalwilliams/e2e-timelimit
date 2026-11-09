//! Client for the LeechProxy policy helper (`python3 -m leechproxy.acl_helper`).
//!
//! Same line protocol Squid uses, plus a trailing count flag:
//!   -> "<id> <client-ip> <client-mac> <sni> <dst> <count 0|1>"
//!   <- "<id> OK message=<pct-encoded>"   (blocked)   |   "<id> ERR"   (allowed)
//! Requests are multiplexed by id. Any failure (helper missing, crashed, slow)
//! fails open: the connection is allowed and the helper is restarted.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::oneshot;

#[derive(Debug, Clone, Default)]
pub struct Decision {
    pub blocked: bool,
    pub message: String,
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Decision>>>>;

struct Running {
    child: Child,
    stdin: ChildStdin,
}

pub struct Helper {
    cmd: Vec<String>,
    running: tokio::sync::Mutex<Option<Running>>,
    pending: Pending,
    next: AtomicU64,
    last_fail: Mutex<Option<Instant>>,
    timeout: Duration,
}

pub fn enc(s: &str) -> String {
    if s.is_empty() {
        return "-".into();
    }
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b".-_:".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

pub fn dec(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_reply(line: &str) -> Option<(u64, Decision)> {
    let mut it = line.split_whitespace();
    let id = it.next()?.parse().ok()?;
    let verdict = it.next()?;
    let mut message = String::new();
    for kv in it {
        if let Some(m) = kv.strip_prefix("message=") {
            message = dec(m);
        }
    }
    Some((id, Decision { blocked: verdict == "OK", message }))
}

impl Helper {
    pub fn new(cmd: Vec<String>) -> Self {
        Helper {
            cmd,
            running: tokio::sync::Mutex::new(None),
            pending: Arc::new(Mutex::new(HashMap::new())),
            next: AtomicU64::new(1),
            last_fail: Mutex::new(None),
            timeout: Duration::from_secs(3),
        }
    }

    fn spawn(&self) -> Option<Running> {
        if let Some(t) = *self.last_fail.lock().unwrap() {
            if t.elapsed() < Duration::from_secs(5) {
                return None; // don't respawn in a tight loop
            }
        }
        let mut child = match Command::new(&self.cmd[0])
            .args(&self.cmd[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("leechproxy-sni: cannot start helper {:?}: {e}", self.cmd);
                *self.last_fail.lock().unwrap() = Some(Instant::now());
                return None;
            }
        };
        let stdin = child.stdin.take()?;
        let stdout = child.stdout.take()?;
        let pending = self.pending.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if let Some((id, d)) = parse_reply(&line) {
                    if let Some(tx) = pending.lock().unwrap().remove(&id) {
                        let _ = tx.send(d);
                    }
                }
            }
            // helper exited: fail all waiters open (dropping senders)
            pending.lock().unwrap().clear();
        });
        Some(Running { child, stdin })
    }

    /// Ask whether `host` is blocked for this client; `count` = charge this minute.
    pub async fn ask(&self, ip: &str, mac: Option<&str>, host: &str, dst: &str, count: bool) -> Decision {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let line = format!(
            "{id} {} {} {} {} {}\n",
            enc(ip),
            enc(mac.unwrap_or("")),
            enc(host),
            enc(dst),
            if count { 1 } else { 0 }
        );
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        {
            let mut guard = self.running.lock().await;
            let alive = match guard.as_mut() {
                Some(r) => matches!(r.child.try_wait(), Ok(None)),
                None => false,
            };
            if !alive {
                *guard = self.spawn();
            }
            let ok = match guard.as_mut() {
                Some(r) => r.stdin.write_all(line.as_bytes()).await.is_ok() && r.stdin.flush().await.is_ok(),
                None => false,
            };
            if !ok {
                *guard = None;
                self.pending.lock().unwrap().remove(&id);
                return Decision::default();
            }
        }
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(d)) => d,
            _ => {
                self.pending.lock().unwrap().remove(&id);
                Decision::default()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes() {
        assert_eq!(enc(""), "-");
        assert_eq!(enc("a b%"), "a%20b%25");
        assert_eq!(enc("aa:bb:cc"), "aa:bb:cc");
        assert_eq!(dec("Social%20media%20%28limit%29"), "Social media (limit)");
        assert_eq!(dec("100%"), "100%");
    }

    #[test]
    fn parses_replies() {
        let (id, d) = parse_reply("12 OK message=Games%20(period)").unwrap();
        assert_eq!((id, d.blocked, d.message.as_str()), (12, true, "Games (period)"));
        let (id, d) = parse_reply("3 ERR").unwrap();
        assert_eq!((id, d.blocked), (3, false));
        assert!(parse_reply("garbage").is_none());
    }
}
