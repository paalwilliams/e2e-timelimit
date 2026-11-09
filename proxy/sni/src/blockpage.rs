//! Block pages for HTTPS.
//!
//! A browser only shows a page for an HTTPS site if it gets a valid TLS session
//! for that hostname. So for *blocked* connections only, we terminate TLS with a
//! certificate issued on the fly by a local CA (which the user installs on their
//! devices) and answer every request with a redirect to the block page.
//! Allowed traffic is never touched: it's spliced before any TLS happens.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

pub const CA_NAME: &str = "LeechProxy Local CA";

pub struct BlockTls {
    ca_cert: Certificate,
    ca_key: KeyPair,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

fn ca_params() -> CertificateParams {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_NAME);
    dn.push(DnType::OrganizationName, "LeechProxy");
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0)); // may only issue leaf certificates
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    p.not_before = rcgen::date_time_ymd(2025, 1, 1);
    p.not_after = rcgen::date_time_ymd(2045, 1, 1);
    p
}

impl BlockTls {
    /// Load the CA from `dir` (ca.pem + ca-key.pem), creating it on first use.
    pub fn load_or_create(dir: &Path) -> Result<Self, String> {
        let key_path: PathBuf = dir.join("ca-key.pem");
        let cert_path: PathBuf = dir.join("ca.pem");
        let ca_key = if key_path.exists() {
            let pem = std::fs::read_to_string(&key_path).map_err(|e| format!("{}: {e}", key_path.display()))?;
            KeyPair::from_pem(&pem).map_err(|e| format!("{}: {e}", key_path.display()))?
        } else {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            let key = KeyPair::generate().map_err(|e| e.to_string())?;
            write_private(&key_path, key.serialize_pem().as_bytes())?;
            let _ = std::fs::remove_file(&cert_path); // a new key needs a new cert
            key
        };
        // Re-deriving the CA certificate from the same key and name gives identical
        // issuer name + key identifier, so leaves verify against the installed ca.pem.
        let ca_cert = ca_params().self_signed(&ca_key).map_err(|e| e.to_string())?;
        if !cert_path.exists() {
            std::fs::write(&cert_path, ca_cert.pem()).map_err(|e| format!("{}: {e}", cert_path.display()))?;
            println!("created local CA {} (install it on devices to see HTTPS block pages)", cert_path.display());
        }
        Ok(BlockTls { ca_cert, ca_key, cache: Mutex::new(HashMap::new()) })
    }

    fn config_for(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        if let Some(c) = self.cache.lock().unwrap().get(host) {
            return Ok(c.clone());
        }
        let mut p = CertificateParams::new(vec![host.to_string()]).map_err(|e| e.to_string())?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        p.distinguished_name = dn;
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.use_authority_key_identifier_extension = true;
        let now = time::OffsetDateTime::now_utc();
        p.not_before = now - time::Duration::days(1);
        p.not_after = now + time::Duration::days(30);
        let key = KeyPair::generate().map_err(|e| e.to_string())?;
        let cert = p.signed_by(&key, &self.ca_cert, &self.ca_key).map_err(|e| e.to_string())?;
        let chain = vec![CertificateDer::from(cert.der().to_vec())];
        let pk = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, pk)
            .map_err(|e| e.to_string())?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        let mut cache = self.cache.lock().unwrap();
        if cache.len() > 2000 {
            cache.clear();
        }
        cache.insert(host.to_string(), cfg.clone());
        Ok(cfg)
    }

    /// Complete a TLS handshake as `host` and answer with `response` (an HTTP/1.1 reply).
    /// `stream` must start at the ClientHello (use `Prefixed` if it was already read).
    pub async fn serve<S>(&self, stream: S, host: &str, response: &[u8]) -> Result<(), String>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let cfg = self.config_for(host)?;
        let mut tls = tokio::time::timeout(Duration::from_secs(10), TlsAcceptor::from(cfg).accept(stream))
            .await
            .map_err(|_| "handshake timeout".to_string())?
            .map_err(|e| format!("handshake: {e}"))?; // e.g. the device doesn't trust our CA
        // Read (and ignore) the request head; browsers wait for the response anyway.
        let mut buf = vec![0u8; 16 * 1024];
        let _ = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf)).await;
        tls.write_all(response).await.map_err(|e| e.to_string())?;
        let _ = tls.shutdown().await;
        Ok(())
    }
}

fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(data).map_err(|e| format!("{}: {e}", path.display()))
}

/// A stream that first replays bytes already read from it (e.g. the peeked ClientHello).
pub struct Prefixed<S> {
    pre: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub fn new(pre: Vec<u8>, inner: S) -> Self {
        Prefixed { pre, pos: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.pre.len() {
            let n = buf.remaining().min(this.pre.len() - this.pos);
            buf.put_slice(&this.pre[this.pos..this.pos + n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn issues_cert_and_serves_block_response() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let dir = std::env::temp_dir().join(format!("leechproxy-ca-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let bt = BlockTls::load_or_create(&dir).unwrap();
        // Reloading the same CA must work and keep ca.pem stable.
        let pem1 = std::fs::read_to_string(dir.join("ca.pem")).unwrap();
        let bt2 = BlockTls::load_or_create(&dir).unwrap();
        assert_eq!(pem1, std::fs::read_to_string(dir.join("ca.pem")).unwrap());
        drop(bt);

        // TLS client that trusts only our ca.pem
        use tokio_rustls::rustls::{ClientConfig, RootCertStore};
        let mut roots = RootCertStore::empty();
        let der = pem_to_der(&pem1);
        roots.add(CertificateDer::from(der)).unwrap();
        let ccfg = Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth());

        let (client, server) = tokio::io::duplex(64 * 1024);
        let srv = tokio::spawn(async move {
            bt2.serve(server, "www.honda.com", b"HTTP/1.1 302 Found\r\nLocation: http://x/blocked\r\nContent-Length: 0\r\n\r\n").await
        });
        let connector = tokio_rustls::TlsConnector::from(ccfg);
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from("www.honda.com").unwrap();
        let mut tls = connector.connect(name, client).await.expect("certificate must verify against our CA");
        tls.write_all(b"GET / HTTP/1.1\r\nHost: www.honda.com\r\n\r\n").await.unwrap();
        let mut resp = String::new();
        let _ = tls.read_to_string(&mut resp).await;
        assert!(resp.starts_with("HTTP/1.1 302"), "{resp}");
        srv.await.unwrap().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn pem_to_der(pem: &str) -> Vec<u8> {
        let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        decode_b64(&b64)
    }

    fn decode_b64(s: &str) -> Vec<u8> {
        let val = |c: u8| match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            _ => 63,
        };
        let bytes: Vec<u8> = s.bytes().filter(|c| *c != b'=').collect();
        let mut out = vec![];
        for chunk in bytes.chunks(4) {
            let mut n = 0u32;
            for (i, c) in chunk.iter().enumerate() {
                n |= (val(*c) as u32) << (18 - 6 * i);
            }
            for i in 0..chunk.len() - 1 {
                out.push((n >> (16 - 8 * i)) as u8);
            }
        }
        out
    }
}
