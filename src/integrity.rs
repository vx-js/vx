use anyhow::{Context, Result, anyhow};
use base64::Engine;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algo {
    Sha512,
    Sha1,
    Sha1Hex,
}

#[derive(Debug, Clone)]
pub struct Integrity {
    pub algo: Algo,
    pub expected: Vec<u8>,
}

impl Integrity {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix("sha512-") {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(rest)
                .context("decode sha512 base64")?;
            return Ok(Self {
                algo: Algo::Sha512,
                expected: bytes,
            });
        }
        if let Some(rest) = s.strip_prefix("sha1-") {
            if let Some(hex) = rest.strip_prefix("hex:") {
                let bytes = decode_hex(hex).context("decode sha1 hex")?;
                return Ok(Self {
                    algo: Algo::Sha1Hex,
                    expected: bytes,
                });
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(rest)
                .context("decode sha1 base64")?;
            return Ok(Self {
                algo: Algo::Sha1,
                expected: bytes,
            });
        }
        Err(anyhow!("unsupported integrity format: {s}"))
    }
}

pub fn hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0xF) as usize] as char);
    }
    out
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(anyhow!("hex length must be even"));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(anyhow!("invalid hex byte")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sha1_hex() {
        let i = Integrity::parse("sha1-hex:da39a3ee5e6b4b0d3255bfef95601890afd80709").unwrap();
        assert_eq!(i.algo, Algo::Sha1Hex);
        assert_eq!(hex(&i.expected), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }
}

