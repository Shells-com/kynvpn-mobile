//! The engine: three threads around one `wg::Handler`.
//!
//! - **outbound** reads the TUN device, encrypts, sends to the server;
//! - **inbound** receives from the server, decrypts, writes to the TUN device
//!   (and answers handshake responses and cookies);
//! - **timers** runs the WireGuard timers (handshake retries, rekeys,
//!   keepalives).
//!
//! The socket sits behind a lock so [`Tunnel::rebind`] can swap it when the
//! phone changes networks; both I/O threads pick the new one up within one
//! poll interval.

use crate::TunDevice;
use kynvpn_core::TunnelConfig;
use pktkit::wg::{self, Handler, NoisePublicKey, PacketType, TimerAction};
use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

/// How long a blocking read waits before checking whether to stop.
const POLL: Duration = Duration::from_millis(250);
/// How often the WireGuard timers run. pktkit asks for ~100 ms; this is the
/// battery cost to remove once it can say when the next timer is due.
const TIMER_TICK: Duration = Duration::from_millis(100);
const MAINTENANCE_EVERY: Duration = Duration::from_secs(10);
/// Packets held while the first handshake completes.
const PENDING_MAX: usize = 64;
/// Largest datagram: an encrypted packet at any MTU we'd configure.
const BUF: usize = 65535;

/// Something the UI should hear about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelEvent {
    /// A handshake with the server completed (first connect, or a rekey).
    HandshakeComplete,
    /// The server didn't answer handshakes for about 90 s.
    HandshakeFailed,
    /// An I/O thread hit an error it couldn't get past and stopped.
    Error(String),
}

/// Traffic counters, for the connection screen.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Wall-clock time of the last completed handshake.
    pub last_handshake: Option<SystemTime>,
}

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("could not resolve endpoint {0}")]
    Resolve(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

struct Inner {
    handler: Arc<Handler>,
    peer: NoisePublicKey,
    endpoint: SocketAddr,
    socket: RwLock<Arc<UdpSocket>>,
    tun: Arc<dyn TunDevice>,
    stop: AtomicBool,
    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,
    last_handshake: Mutex<Option<SystemTime>>,
    pending: Mutex<VecDeque<Vec<u8>>>,
    on_event: Box<dyn Fn(TunnelEvent) + Send + Sync>,
}

/// A running tunnel. Dropping it stops it.
pub struct Tunnel {
    inner: Arc<Inner>,
    threads: Vec<JoinHandle<()>>,
}

impl Tunnel {
    /// Bring the tunnel up and send the first handshake.
    ///
    /// `endpoint` is the server's address, resolved by the caller (outside
    /// the tunnel, see [`kynvpn_core::PeerConfig::endpoint`]). `socket` must
    /// already be protected from the tunnel's routes on Android.
    pub fn start(
        cfg: &TunnelConfig,
        endpoint: SocketAddr,
        tun: Arc<dyn TunDevice>,
        socket: UdpSocket,
        on_event: impl Fn(TunnelEvent) + Send + Sync + 'static,
    ) -> Result<Self, TunnelError> {
        let handler =
            Handler::new(wg::Config::default().private_key(cfg.private_key.to_private()))?;
        let peer = cfg.peer.public_key.to_public();
        match &cfg.peer.preshared_key {
            Some(psk) => handler.add_peer_with_psk(peer, psk.to_preshared()),
            None => handler.add_peer(peer),
        }
        handler.set_persistent_keepalive(&peer, cfg.peer.persistent_keepalive);
        socket.set_read_timeout(Some(POLL))?;

        let inner = Arc::new(Inner {
            handler,
            peer,
            endpoint,
            socket: RwLock::new(Arc::new(socket)),
            tun,
            stop: AtomicBool::new(false),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            last_handshake: Mutex::new(None),
            pending: Mutex::new(VecDeque::new()),
            on_event: Box::new(on_event),
        });

        let init = inner.handler.initiate_handshake(&peer)?;
        inner.send(&init);

        let spawn = |name: &str, f: fn(&Inner)| {
            let i = inner.clone();
            std::thread::Builder::new()
                .name(name.into())
                .spawn(move || f(&i))
        };
        let threads = vec![
            spawn("kyn-out", Inner::outbound)?,
            spawn("kyn-in", Inner::inbound)?,
            spawn("kyn-timers", Inner::timers)?,
        ];
        Ok(Self { inner, threads })
    }

    /// Switch to a new UDP socket after a network change. The session
    /// carries on; a keepalive goes out at once so the server learns our new
    /// address without waiting for traffic.
    pub fn rebind(&self, socket: UdpSocket) -> io::Result<()> {
        socket.set_read_timeout(Some(POLL))?;
        *self.inner.socket.write().expect("socket lock") = Arc::new(socket);
        if let Ok(ka) = self.inner.handler.generate_keepalive(&self.inner.peer) {
            self.inner.send(&ka);
        }
        Ok(())
    }

    pub fn stats(&self) -> Stats {
        Stats {
            rx_bytes: self.inner.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: self.inner.tx_bytes.load(Ordering::Relaxed),
            last_handshake: *self.inner.last_handshake.lock().expect("stats lock"),
        }
    }

    pub fn is_connected(&self) -> bool {
        self.inner.handler.has_session(&self.inner.peer)
    }

    /// Stop the threads and wait for them (at most one poll interval).
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.inner.stop.store(true, Ordering::Relaxed);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        let _ = self.inner.handler.close();
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl Inner {
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    fn socket(&self) -> Arc<UdpSocket> {
        self.socket.read().expect("socket lock").clone()
    }

    fn send(&self, datagram: &[u8]) {
        // Losing a datagram is normal on a phone (no route for a moment
        // during a network change); WireGuard's timers recover.
        let _ = self.socket().send_to(datagram, self.endpoint);
    }

    fn fail(&self, what: &str, e: io::Error) {
        (self.on_event)(TunnelEvent::Error(format!("{what}: {e}")));
    }

    fn outbound(&self) {
        let mut buf = vec![0u8; BUF];
        while !self.stopped() {
            let n = match self.tun.read(&mut buf, POLL) {
                Ok(Some(n)) if n > 0 => n,
                Ok(_) => continue,
                Err(e) => return self.fail("tun read", e),
            };
            let packet = &buf[..n];
            if self.handler.has_session(&self.peer) {
                if let Ok(ct) = self.handler.encrypt(packet, &self.peer) {
                    self.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                    self.send(&ct);
                }
            } else {
                let mut q = self.pending.lock().expect("pending lock");
                if q.len() == PENDING_MAX {
                    q.pop_front();
                }
                q.push_back(packet.to_vec());
            }
        }
    }

    fn inbound(&self) {
        let mut buf = vec![0u8; BUF];
        while !self.stopped() {
            let socket = self.socket();
            let (n, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                // A socket replaced by rebind() may error once it's dropped.
                Err(_) if !Arc::ptr_eq(&socket, &self.socket()) => continue,
                Err(e) => return self.fail("udp recv", e),
            };
            if from != self.endpoint {
                continue;
            }
            let Ok(r) = self.handler.process_packet(&buf[..n], &from) else {
                continue;
            };
            match r.ty {
                PacketType::TransportData => {
                    self.rx_bytes
                        .fetch_add(r.data.len() as u64, Ordering::Relaxed);
                    if let Err(e) = self.tun.write(&r.data) {
                        return self.fail("tun write", e);
                    }
                }
                PacketType::HandshakeResponse => {
                    if !r.response.is_empty() {
                        self.send(&r.response);
                    }
                    *self.last_handshake.lock().expect("stats lock") = Some(SystemTime::now());
                    self.flush_pending();
                    (self.on_event)(TunnelEvent::HandshakeComplete);
                }
                PacketType::CookieReply => self.send(&r.response),
                PacketType::CookieReceived => {
                    if let Ok(init) = self.handler.initiate_handshake(&self.peer) {
                        self.send(&init);
                    }
                }
                PacketType::Keepalive => {}
            }
        }
    }

    fn flush_pending(&self) {
        let queued: Vec<_> = self
            .pending
            .lock()
            .expect("pending lock")
            .drain(..)
            .collect();
        for p in queued {
            if let Ok(ct) = self.handler.encrypt(&p, &self.peer) {
                self.tx_bytes.fetch_add(p.len() as u64, Ordering::Relaxed);
                self.send(&ct);
            }
        }
    }

    fn timers(&self) {
        let mut last_maintenance = Instant::now();
        while !self.stopped() {
            std::thread::sleep(TIMER_TICK);
            for action in self.handler.poll_timers() {
                match action {
                    TimerAction::SendHandshake { packet, .. }
                    | TimerAction::SendKeepalive { packet, .. } => self.send(&packet),
                    TimerAction::HandshakeFailed { .. } => {
                        self.pending.lock().expect("pending lock").clear();
                        (self.on_event)(TunnelEvent::HandshakeFailed);
                    }
                    _ => {}
                }
            }
            if last_maintenance.elapsed() >= MAINTENANCE_EVERY {
                self.handler.maintenance();
                last_maintenance = Instant::now();
            }
        }
    }
}
