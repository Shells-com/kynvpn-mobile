//! One tunnel's configuration: the interface (our key, addresses, DNS, MTU)
//! and the single server peer.

use crate::key::{Key, KeyError};
use pktkit::IpPrefix;
use std::net::IpAddr;
use std::time::Duration;

/// What the tunnel needs to come up. On Android the interface half goes to
/// `VpnService.Builder`, on iOS to `NEPacketTunnelNetworkSettings`; the peer
/// half goes to the WireGuard engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelConfig {
    pub private_key: Key,
    /// The addresses the tunnel interface gets (`10.x.y.z/32`, `fd00::…/128`).
    pub addresses: Vec<IpPrefix>,
    pub dns: Vec<IpAddr>,
    pub mtu: u16,
    pub peer: PeerConfig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerConfig {
    pub public_key: Key,
    pub preshared_key: Option<Key>,
    /// `host:port`. Resolved by the platform layer before the tunnel's own
    /// routes exist, so the lookup doesn't go into the tunnel.
    pub endpoint: String,
    /// The routes sent into the tunnel: `0.0.0.0/0` and `::/0` for full tunnel.
    pub allowed_ips: Vec<IpPrefix>,
    pub persistent_keepalive: Option<Duration>,
}

/// The MTU wg-quick uses when none is given: 1500 minus the worst-case
/// (IPv6) WireGuard overhead.
pub const DEFAULT_MTU: u16 = 1420;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("line {line}: {msg}")]
    Syntax { line: usize, msg: String },
    #[error("line {line}: bad key: {source}")]
    Key { line: usize, source: KeyError },
    #[error("missing {0}")]
    Missing(&'static str),
    #[error("exactly one [Peer] is supported, found {0}")]
    PeerCount(usize),
}

impl TunnelConfig {
    /// Parse a `wg-quick` style configuration with one `[Peer]`.
    ///
    /// This is the manual way in until the kynvpn backend hands out
    /// configurations. wg-quick-only keys (`PostUp`, `Table`, …) are refused
    /// rather than silently ignored, since they can't apply on a phone.
    pub fn from_wg_quick(text: &str) -> Result<Self, ConfigError> {
        #[derive(PartialEq)]
        enum Section {
            None,
            Interface,
            Peer,
        }
        let mut section = Section::None;
        let mut private_key = None;
        let mut addresses = Vec::new();
        let mut dns = Vec::new();
        let mut mtu = None;
        let mut peers = 0usize;
        let mut public_key = None;
        let mut preshared_key = None;
        let mut endpoint = None;
        let mut allowed_ips = Vec::new();
        let mut keepalive = None;

        for (i, raw) in text.lines().enumerate() {
            let line = i + 1;
            let l = raw.split('#').next().unwrap_or("").trim();
            if l.is_empty() {
                continue;
            }
            let syntax = |msg: String| ConfigError::Syntax { line, msg };
            if l.starts_with('[') {
                section = match l.to_ascii_lowercase().as_str() {
                    "[interface]" => Section::Interface,
                    "[peer]" => {
                        peers += 1;
                        Section::Peer
                    }
                    _ => return Err(syntax(format!("unknown section {l}"))),
                };
                continue;
            }
            let (k, v) = l
                .split_once('=')
                .ok_or_else(|| syntax("expected key = value".into()))?;
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
            let key = |v: &str| {
                v.parse::<Key>()
                    .map_err(|source| ConfigError::Key { line, source })
            };
            let list = |v: &str| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect::<Vec<_>>()
            };
            let prefix = |s: &str| -> Result<IpPrefix, ConfigError> {
                if s.contains('/') {
                    s.parse().map_err(|_| syntax(format!("bad prefix {s}")))
                } else {
                    let a: IpAddr = s.parse().map_err(|_| syntax(format!("bad address {s}")))?;
                    Ok(IpPrefix::new(a, if a.is_ipv4() { 32 } else { 128 }))
                }
            };
            match (&section, k.as_str()) {
                (Section::Interface, "privatekey") => private_key = Some(key(v)?),
                (Section::Interface, "address") => {
                    for a in list(v) {
                        addresses.push(prefix(&a)?);
                    }
                }
                (Section::Interface, "dns") => {
                    for d in list(v) {
                        // wg-quick also takes search domains here; we don't use them yet.
                        if let Ok(a) = d.parse() {
                            dns.push(a);
                        }
                    }
                }
                (Section::Interface, "mtu") => {
                    mtu = Some(v.parse().map_err(|_| syntax(format!("bad MTU {v}")))?)
                }
                (Section::Interface, "listenport") => {}
                (Section::Peer, "publickey") => public_key = Some(key(v)?),
                (Section::Peer, "presharedkey") => preshared_key = Some(key(v)?),
                (Section::Peer, "endpoint") => endpoint = Some(v.to_string()),
                (Section::Peer, "allowedips") => {
                    for a in list(v) {
                        allowed_ips.push(prefix(&a)?);
                    }
                }
                (Section::Peer, "persistentkeepalive") => {
                    let s: u64 = if v.eq_ignore_ascii_case("off") {
                        0
                    } else {
                        v.parse()
                            .map_err(|_| syntax(format!("bad keepalive {v}")))?
                    };
                    keepalive = (s > 0).then(|| Duration::from_secs(s));
                }
                (Section::None, _) => return Err(syntax("key outside a section".into())),
                (_, other) => return Err(syntax(format!("unsupported key {other}"))),
            }
        }

        if peers != 1 {
            return Err(ConfigError::PeerCount(peers));
        }
        Ok(TunnelConfig {
            private_key: private_key.ok_or(ConfigError::Missing("Interface.PrivateKey"))?,
            addresses,
            dns,
            mtu: mtu.unwrap_or(DEFAULT_MTU),
            peer: PeerConfig {
                public_key: public_key.ok_or(ConfigError::Missing("Peer.PublicKey"))?,
                preshared_key,
                endpoint: endpoint.ok_or(ConfigError::Missing("Peer.Endpoint"))?,
                allowed_ips,
                persistent_keepalive: keepalive,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.64.0.2/32, fd00:64::2
DNS = 10.64.0.1, example.internal

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = vpn.example.net:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25 # behind NAT
";

    #[test]
    fn parses_wg_quick() {
        let c = TunnelConfig::from_wg_quick(SAMPLE).unwrap();
        assert_eq!(c.addresses.len(), 2);
        assert_eq!(c.addresses[1].bits(), 128);
        assert_eq!(c.dns, vec!["10.64.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(c.mtu, DEFAULT_MTU);
        assert_eq!(c.peer.endpoint, "vpn.example.net:51820");
        assert_eq!(c.peer.allowed_ips.len(), 2);
        assert_eq!(c.peer.persistent_keepalive, Some(Duration::from_secs(25)));
    }

    #[test]
    fn refuses_hooks_and_multiple_peers() {
        let hooked = SAMPLE.replace("[Peer]", "PostUp = iptables -A ...\n[Peer]");
        assert!(matches!(
            TunnelConfig::from_wg_quick(&hooked),
            Err(ConfigError::Syntax { .. })
        ));
        let two =
            format!("{SAMPLE}\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n");
        assert_eq!(
            TunnelConfig::from_wg_quick(&two),
            Err(ConfigError::PeerCount(2))
        );
    }
}
