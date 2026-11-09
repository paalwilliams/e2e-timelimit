//! Peeking at the first bytes of a connection: TLS ClientHello SNI and HTTP Host.

#[derive(Debug, PartialEq)]
pub enum Peek<T> {
    /// Parsed successfully.
    Done(T),
    /// Need more bytes.
    More,
    /// Not this protocol / malformed.
    Invalid,
}

fn be16(b: &[u8], i: usize) -> Option<usize> {
    Some(((*b.get(i)? as usize) << 8) | *b.get(i + 1)? as usize)
}

/// SNI hostname from a TLS ClientHello. `Done(None)` = valid ClientHello without SNI.
pub fn sni(data: &[u8]) -> Peek<Option<String>> {
    if data.len() < 5 {
        return Peek::More;
    }
    if data[0] != 0x16 || data[1] != 0x03 {
        return Peek::Invalid;
    }
    let rec_len = be16(data, 3).unwrap();
    if data.len() < 5 + rec_len {
        return Peek::More;
    }
    match parse_client_hello(&data[5..5 + rec_len]) {
        Some(v) => Peek::Done(v),
        None => Peek::Invalid,
    }
}

fn parse_client_hello(b: &[u8]) -> Option<Option<String>> {
    if *b.first()? != 0x01 {
        return None;
    }
    let mut p = 4 + 2 + 32; // handshake header, client_version, random
    p += 1 + *b.get(p)? as usize; // session_id
    p += 2 + be16(b, p)?; // cipher_suites
    p += 1 + *b.get(p)? as usize; // compression_methods
    if p + 2 > b.len() {
        return Some(None); // no extensions
    }
    let end = (p + 2 + be16(b, p)?).min(b.len());
    p += 2;
    while p + 4 <= end {
        let etype = be16(b, p)?;
        let elen = be16(b, p + 2)?;
        p += 4;
        if etype == 0 {
            // server_name extension: list length, then (type, len, name)*
            let mut q = p + 2;
            while q + 3 <= (p + elen).min(b.len()) {
                let ntype = b[q];
                let nlen = be16(b, q + 1)?;
                if ntype == 0 {
                    let name = b.get(q + 3..q + 3 + nlen)?;
                    return Some(Some(String::from_utf8_lossy(name).to_ascii_lowercase()));
                }
                q += 3 + nlen;
            }
            return Some(None);
        }
        p += elen;
    }
    Some(None)
}

/// Host header (without port) from an HTTP/1.x request head, plus the head length.
pub fn http_host(data: &[u8]) -> Peek<(Option<String>, usize)> {
    let end = match find(data, b"\r\n\r\n") {
        Some(e) => e,
        None => {
            return if data.len() > 16 * 1024 || !looks_like_http(data) { Peek::Invalid } else { Peek::More };
        }
    };
    let head = String::from_utf8_lossy(&data[..end]);
    for line in head.split("\r\n").skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("host") {
                return Peek::Done((Some(strip_port(v.trim()).to_ascii_lowercase()), end + 4));
            }
        }
    }
    Peek::Done((None, end + 4))
}

fn looks_like_http(data: &[u8]) -> bool {
    data.iter().take(8).all(|c| c.is_ascii_graphic() || *c == b' ')
}

pub fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// "example.com:8080" -> "example.com", "[::1]:80" -> "::1"
pub fn strip_port(h: &str) -> &str {
    if let Some(rest) = h.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match h.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) && !host.contains(':') => host,
        _ => h,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real ClientHello for "www.example.com" (trimmed, valid structure).
    fn client_hello(host: &str) -> Vec<u8> {
        let name = host.as_bytes();
        let mut sni_ext = vec![];
        let list_len = 3 + name.len();
        sni_ext.extend_from_slice(&[0x00, 0x00]); // type server_name
        sni_ext.extend_from_slice(&((list_len + 2) as u16).to_be_bytes());
        sni_ext.extend_from_slice(&(list_len as u16).to_be_bytes());
        sni_ext.push(0);
        sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name);
        let other_ext = [0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]; // ec_point_formats
        let mut exts = other_ext.to_vec();
        exts.extend_from_slice(&sni_ext);

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]); // random
        body.push(32);
        body.extend_from_slice(&[9u8; 32]); // session id
        body.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]); // ciphers
        body.extend_from_slice(&[0x01, 0x00]); // compression
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn parses_sni() {
        let ch = client_hello("www.Example.com");
        assert_eq!(sni(&ch), Peek::Done(Some("www.example.com".into())));
        assert_eq!(sni(&ch[..ch.len() - 3]), Peek::More);
        assert_eq!(sni(&ch[..3]), Peek::More);
        assert_eq!(sni(b"GET / HTTP/1.1\r\n"), Peek::Invalid);
    }

    #[test]
    fn parses_http_host() {
        let req = b"GET / HTTP/1.1\r\nUser-Agent: x\r\nHost: Example.com:8080\r\n\r\nbody";
        assert_eq!(http_host(req), Peek::Done((Some("example.com".into()), req.len() - 4)));
        assert_eq!(http_host(b"GET / HTTP/1.1\r\nHost: a"), Peek::More);
        assert_eq!(http_host(b"\x16\x03\x01\x02\x00\x01\x00\x01"), Peek::Invalid);
    }

    #[test]
    fn strips_ports() {
        assert_eq!(strip_port("a.com:443"), "a.com");
        assert_eq!(strip_port("[::1]:80"), "::1");
        assert_eq!(strip_port("a.com"), "a.com");
    }
}
