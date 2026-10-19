// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Peer-to-peer between engines of one test, on loopback, as the service
//! runs it (storage format 3): each device has its TLS certificate and a
//! signed peer record on the storage; a serving device answers TLS over
//! TCP for the devices its directory names; an asking device builds its
//! peer table from its own directory.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use varsto_core::p2p::{self, v3, Snapshot};
use varsto_core::Engine;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Publish `e`'s peer record for `port` on loopback (its certificate is
/// made on first use): devices that read it admit and reach `e`.
pub fn publish(e: &Engine, port: u16) {
    e.p2p_identity().unwrap();
    let mut body = e.peer_body(port);
    body.lan_addrs = vec![LOOPBACK];
    body.udp_local = Vec::new();
    e.publish_peer_body(&mut body).unwrap();
}

/// A device serving its snapshot over TLS on loopback until dropped.
pub struct Serving {
    pub addr: SocketAddr,
    pub responder: Arc<v3::Responder>,
    snap: Arc<Mutex<Option<Arc<Snapshot>>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Serving {
    /// `e` listens on loopback and publishes its peer record there.
    pub fn start(e: &mut Engine) -> Serving {
        let identity = e.p2p_identity().unwrap();
        let responder = e.p2p_responder(&identity);
        let tls = v3::tls::TcpTls::new(&identity, responder.clone()).unwrap();
        let server = p2p::Server::bind("127.0.0.1:0".parse().unwrap(), tls).unwrap();
        let addr = server.addr;
        publish(e, addr.port());
        let snap: Arc<Mutex<Option<Arc<Snapshot>>>> =
            Arc::new(Mutex::new(Some(Arc::new(e.peer_snapshot().unwrap()))));
        let stop = Arc::new(AtomicBool::new(false));
        let (s2, st2) = (snap.clone(), stop.clone());
        let thread = std::thread::spawn(move || server.run(s2, st2));
        Serving {
            addr,
            responder,
            snap,
            stop,
            thread: Some(thread),
        }
    }

    /// Where the server takes its snapshot from, for
    /// `Engine::set_snapshot_sink` (as the service hands it over).
    pub fn sink(&self) -> Snap {
        self.snap.clone()
    }

    /// Read `e`'s membership and the peer records again (the server
    /// admits the devices it reads now) and serve a fresh snapshot.
    pub fn refresh(&self, e: &mut Engine) {
        e.refresh_devices().unwrap();
        self.responder.set_directory(e.peer_directory().unwrap());
        *self.snap.lock().unwrap() = Some(Arc::new(e.peer_snapshot().unwrap()));
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// `e` reads the directory and asks its peers over TLS on TCP.
pub fn meet(e: &mut Engine) {
    e.refresh_devices().unwrap();
    let peers = e.p2p_peers_tcp().expect("a peer record to reach");
    e.set_peers(Some(Arc::new(peers)));
}

pub type Snap = Arc<Mutex<Option<Arc<Snapshot>>>>;

/// What `e` serves to peers right now.
pub fn served(e: &Engine) -> Snap {
    Arc::new(Mutex::new(Some(Arc::new(e.peer_snapshot().unwrap()))))
}

/// Nothing to serve (a locked service).
pub fn empty() -> Snap {
    Arc::new(Mutex::new(None))
}

/// A device's QUIC node on a loopback port of its own, as the service
/// runs it, with the answering and asking sides it uses.
pub struct QuicDev {
    pub node: Arc<p2p::quic::Node>,
    pub responder: Arc<v3::Responder>,
    pub client: Arc<v3::Client>,
}

pub fn quic_node(e: &Engine, snap: Snap, traffic: Arc<p2p::Traffic>) -> QuicDev {
    traffic.set_me(e.device_id(), e.own_device_name());
    let identity = e.p2p_identity().unwrap();
    let responder = e.p2p_responder(&identity);
    let node = p2p::quic::Node::start_v3(
        "127.0.0.1:0".parse().unwrap(),
        identity.clone(),
        responder.clone(),
        snap,
        traffic,
    )
    .unwrap();
    QuicDev {
        node,
        responder,
        client: e.p2p_client(identity),
    }
}

/// Publish `e`'s peer record for its QUIC node: no TCP address (on
/// loopback, a LAN address, TCP would be tried first); the node's address
/// as its only UDP address when `direct` (none, as behind a NAT,
/// otherwise); reachable and relays as given.
pub fn publish_quic(
    e: &Engine,
    d: &QuicDev,
    direct: bool,
    reachable: bool,
    relay_via: &[varsto_core::ids::DeviceId],
) {
    let mut body = e.peer_body(d.node.local_addr.port());
    body.lan_addrs.clear();
    body.public_addrs.clear();
    body.udp_local = if direct {
        vec![d.node.local_addr]
    } else {
        Vec::new()
    };
    body.reachable = reachable;
    body.relay_via = relay_via
        .iter()
        .map(|r| varsto_core::record::id16(r).unwrap())
        .collect();
    e.publish_peer_body(&mut body).unwrap();
}

/// `e` reads the membership and the peer records: its node admits the
/// devices of the directory, and the table reaches them over QUIC (and
/// TCP where a record has a TCP address).
pub fn quic_table(e: &mut Engine, d: &QuicDev) -> p2p::Peers {
    e.refresh_devices().unwrap();
    let dir = e.peer_directory().unwrap();
    d.responder.set_directory(dir.clone());
    p2p::Peers::build_v3(d.client.clone(), &dir, &[], Some(d.node.clone()))
}

/// `server` (serving on `serving`) and every one of `clients` know each
/// other: the clients publish their records (no listener of their own),
/// the server reads them, and the clients build their peer tables.
pub fn connect(server: &mut Engine, serving: &Serving, clients: &mut [&mut Engine]) {
    for c in clients.iter() {
        publish(c, 9);
    }
    serving.refresh(server);
    for c in clients.iter_mut() {
        meet(c);
    }
}
