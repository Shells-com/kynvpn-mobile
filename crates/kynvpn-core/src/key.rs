//! WireGuard keys: 32 bytes, written as standard padded base64.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use pktkit::wg::{self, NoisePresharedKey, NoisePrivateKey, NoisePublicKey};
use std::fmt;
use std::str::FromStr;

/// A 32-byte WireGuard key (private, public or preshared).
///
/// `Debug` never prints the bytes, so a private key can't leak into a log.
#[derive(Clone, PartialEq, Eq)]
pub struct Key([u8; 32]);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("key is not valid base64")]
    Base64,
    #[error("key is {0} bytes, expected 32")]
    Length(usize),
    #[error("could not generate a key: {0}")]
    Random(String),
}

impl Key {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// A fresh, clamped Curve25519 private key from the OS's random source.
    pub fn generate_private() -> Result<Self, KeyError> {
        let k = wg::generate_private_key().map_err(|e| KeyError::Random(e.to_string()))?;
        Ok(Self(*k.as_bytes()))
    }

    /// The public key of this private key.
    pub fn public_key(&self) -> Result<Key, KeyError> {
        let h = wg::Handler::new(wg::Config::default().private_key(self.to_private()))
            .map_err(|e| KeyError::Random(e.to_string()))?;
        Ok(Self(*h.public_key().as_bytes()))
    }

    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.0)
    }

    pub fn to_private(&self) -> NoisePrivateKey {
        NoisePrivateKey::from(self.0)
    }

    pub fn to_public(&self) -> NoisePublicKey {
        NoisePublicKey::from(self.0)
    }

    pub fn to_preshared(&self) -> NoisePresharedKey {
        NoisePresharedKey::from(self.0)
    }
}

impl FromStr for Key {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, KeyError> {
        let v = STANDARD.decode(s.trim()).map_err(|_| KeyError::Base64)?;
        let bytes: [u8; 32] = v
            .as_slice()
            .try_into()
            .map_err(|_| KeyError::Length(v.len()))?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(..)")
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // Best effort; volatile so the compiler keeps the store.
        for b in &mut self.0 {
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trip() {
        let k = Key::generate_private().unwrap();
        let s = k.to_base64();
        assert_eq!(s.len(), 44);
        assert_eq!(s.parse::<Key>().unwrap(), k);
    }

    #[test]
    fn rejects_bad_keys() {
        assert_eq!("not base64!".parse::<Key>(), Err(KeyError::Base64));
        assert_eq!("AAAA".parse::<Key>(), Err(KeyError::Length(3)));
    }

    #[test]
    fn public_key_matches_rfc7748() {
        // RFC 7748 §6.1: Alice's private and public key.
        let private = Key::from_bytes(hex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let public = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(private.public_key().unwrap().as_bytes(), &public);
    }

    #[test]
    fn debug_hides_bytes() {
        assert_eq!(format!("{:?}", Key::from_bytes([7; 32])), "Key(..)");
    }

    fn hex(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }
}
