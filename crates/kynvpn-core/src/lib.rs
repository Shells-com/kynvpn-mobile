//! Platform-neutral kynvpn client logic.
//!
//! Nothing here touches a socket, a TUN device or the UI: it is the model the
//! app shows and the tunnel runs from, so it builds and tests on any host.
//!
//! - [`key`]: WireGuard keys (base64 in and out, generation, public from private).
//! - [`config`]: one tunnel's configuration, and a `wg-quick` parser for
//!   bringing one up by hand while the kynvpn backend is being built.
//! - [`source`]: where configurations come from. Today only a static one;
//!   the kynvpn API will be another implementation.

pub mod config;
pub mod key;
pub mod source;

pub use config::{ConfigError, PeerConfig, TunnelConfig};
pub use key::{Key, KeyError};
