//! The kynvpn WireGuard engine.
//!
//! [`Tunnel`] drives pktkit's sans-I/O [`pktkit::wg::Handler`] between a
//! [`TunDevice`] (the OS's side of the VPN) and a UDP socket (the server's
//! side). The platform layer owns both ends:
//!
//! - **Android**: `VpnService.Builder.establish()` gives the TUN fd
//!   ([`FdTun`]); the UDP socket is created here and passed to
//!   `VpnService.protect()` before [`Tunnel::start`], so its packets don't
//!   loop back into the tunnel.
//! - **iOS**: the Packet Tunnel extension's `packetFlow`, or its utun fd
//!   ([`FdTun`] with [`FdTun::with_af_header`]); sockets made inside the
//!   extension aren't routed into its own tunnel.
//!
//! When the network changes (Wi-Fi to cellular), the platform layer makes a
//! new socket and calls [`Tunnel::rebind`]; the WireGuard session survives.

mod engine;
#[cfg(unix)]
mod tun;

pub use engine::{Stats, Tunnel, TunnelError, TunnelEvent};
#[cfg(unix)]
pub use tun::FdTun;

use std::io;
use std::time::Duration;

/// The OS's side of the tunnel: whole IP packets, one per call.
pub trait TunDevice: Send + Sync + 'static {
    /// Read one packet into `buf`. `Ok(None)` when nothing arrived within
    /// `timeout`, so the engine can notice it's being stopped.
    fn read(&self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<usize>>;

    /// Write one packet.
    fn write(&self, packet: &[u8]) -> io::Result<()>;
}
