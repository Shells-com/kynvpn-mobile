//! The engine against a real WireGuard responder (pktkit's Handler) on
//! localhost: handshake, packets both ways, counters, and a rebind.

use kynvpn_core::{Key, PeerConfig, TunnelConfig};
use kynvpn_tunnel::{TunDevice, Tunnel, TunnelEvent};
use pktkit::wg::{self, Handler, PacketType};
use std::io;
use std::net::UdpSocket;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A TUN device made of two channels.
struct MemTun {
    to_engine: Mutex<Receiver<Vec<u8>>>,
    from_engine: Sender<Vec<u8>>,
}

impl TunDevice for MemTun {
    fn read(&self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<usize>> {
        match self.to_engine.lock().unwrap().recv_timeout(timeout) {
            Ok(p) => {
                buf[..p.len()].copy_from_slice(&p);
                Ok(Some(p.len()))
            }
            Err(_) => Ok(None),
        }
    }
    fn write(&self, packet: &[u8]) -> io::Result<()> {
        let _ = self.from_engine.send(packet.to_vec());
        Ok(())
    }
}

/// A fake IPv4 packet: the engine doesn't parse them, only the OS does.
fn packet(tag: u8) -> Vec<u8> {
    let mut p = vec![0x45, 0, 0, 28];
    p.extend(std::iter::repeat_n(tag, 24));
    p
}

#[test]
fn handshake_traffic_and_rebind() {
    let server_key = Key::generate_private().unwrap();
    let client_key = Key::generate_private().unwrap();

    // The server: echo every transport packet back to whoever sent it.
    let server_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    server_sock
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let endpoint = server_sock.local_addr().unwrap();
    let server = Handler::new(wg::Config::default().private_key(server_key.to_private())).unwrap();
    let client_pub = client_key.public_key().unwrap().to_public();
    server.add_peer(client_pub);
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, from)) = server_sock.recv_from(&mut buf) {
            let Ok(r) = server.process_packet(&buf[..n], &from) else {
                continue;
            };
            if !r.response.is_empty() {
                server_sock.send_to(&r.response, from).unwrap();
            }
            if r.ty == PacketType::TransportData {
                let ct = server.encrypt(&r.data, &client_pub).unwrap();
                server_sock.send_to(&ct, from).unwrap();
            }
        }
    });

    let cfg = TunnelConfig {
        private_key: client_key,
        addresses: vec!["10.0.0.2/32".parse().unwrap()],
        dns: vec![],
        mtu: 1420,
        peer: PeerConfig {
            public_key: server_key.public_key().unwrap(),
            preshared_key: None,
            endpoint: endpoint.to_string(),
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            persistent_keepalive: None,
        },
    };
    let (to_engine_tx, to_engine_rx) = channel();
    let (from_engine_tx, from_engine_rx) = channel();
    let tun = Arc::new(MemTun {
        to_engine: Mutex::new(to_engine_rx),
        from_engine: from_engine_tx,
    });
    let (ev_tx, ev_rx) = channel();
    let ev_tx = Mutex::new(ev_tx);
    let tunnel = Tunnel::start(
        &cfg,
        endpoint,
        tun,
        UdpSocket::bind("127.0.0.1:0").unwrap(),
        move |e| {
            let _ = ev_tx.lock().unwrap().send(e);
        },
    )
    .unwrap();

    // Sent before the handshake completes: held, then delivered.
    to_engine_tx.send(packet(1)).unwrap();
    assert_eq!(
        ev_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        TunnelEvent::HandshakeComplete
    );
    assert_eq!(
        from_engine_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        packet(1)
    );
    assert!(tunnel.is_connected());

    // A network change: new socket, same session.
    tunnel
        .rebind(UdpSocket::bind("127.0.0.1:0").unwrap())
        .unwrap();
    to_engine_tx.send(packet(2)).unwrap();
    assert_eq!(
        from_engine_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        packet(2)
    );

    let s = tunnel.stats();
    assert_eq!(s.tx_bytes, 56);
    assert_eq!(s.rx_bytes, 56);
    assert!(s.last_handshake.is_some());
    tunnel.stop();
}
