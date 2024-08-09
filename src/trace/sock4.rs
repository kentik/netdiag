use std::convert::TryFrom;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use std::sync::Arc;
use anyhow::Result;
use etherparse::{IpNumber, Ipv4Header, TcpHeaderSlice};
use libc::{IPPROTO_TCP, IPPROTO_UDP, c_int};
use log::{debug, error};
use raw_socket::tokio::prelude::*;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use crate::{Bind, RouteSocket};
use super::probe::{Key, Probe};
use super::reply::Echo;
use super::state::State;

pub struct Sock4 {
    icmp:  Mutex<Arc<RawSocket>>,
    tcp:   Mutex<Arc<RawSocket>>,
    udp:   Mutex<Arc<RawSocket>>,
    route: Mutex<RouteSocket>,
    _join_set: JoinSet<()>,
}

impl Sock4 {
    pub async fn new(bind: &Bind, icmp: Arc<RawSocket>, state: Arc<State>) -> Result<Self> {
        let ipv4  = Domain::ipv4();
        let tcp   = Protocol::from(IPPROTO_TCP);
        let udp   = Protocol::from(IPPROTO_UDP);

        let tcp   = Arc::new(RawSocket::new(ipv4, Type::raw(), Some(tcp))?);
        let udp   = Arc::new(RawSocket::new(ipv4, Type::raw(), Some(udp))?);
        let route = RouteSocket::new(bind.sa4()).await?;

        tcp.bind(bind.sa4()).await?;
        udp.bind(bind.sa4()).await?;

        let enable: c_int = 6;
        tcp.set_sockopt(Level::IPV4, Name::IPV4_HDRINCL, &enable)?;
        udp.set_sockopt(Level::IPV4, Name::IPV4_HDRINCL, &enable)?;

        let mut join_set = JoinSet::new();

        let rx = tcp.clone();
        join_set.spawn(async move {
            match recv(rx, state).await {
                Ok(()) => debug!("recv finished"),
                Err(e) => error!("recv failed: {}", e),
            }
        });

        Ok(Self {
            icmp:  Mutex::new(icmp),
            tcp:   Mutex::new(tcp),
            udp:   Mutex::new(udp),
            route: Mutex::new(route),
            _join_set: join_set,
        })
    }

    pub async fn send(&self, probe: &Probe, ttl: u8) -> Result<Instant> {
        let mut pkt = [0u8; 64];

        let pkt = probe.encode(&mut pkt, ttl)?;
        let dst = probe.dst();

        if cfg!(target_os = "macos") {
            let len = u16::try_from(pkt.len())?;
            pkt[2..4].copy_from_slice(&len.to_ne_bytes());
            pkt[6..8].copy_from_slice(&0u16.to_ne_bytes());
        }

        match probe {
            Probe::ICMP(..) => self.icmp.lock().await,
            Probe::TCP(..)  => self.tcp.lock().await,
            Probe::UDP(..)  => self.udp.lock().await,
        }.send_to(pkt, &dst).await?;

        Ok(Instant::now())
    }

    pub async fn source(&self, dst: IpAddr) -> Result<IpAddr> {
        let mut route = self.route.lock().await;
        route.source(SocketAddr::new(dst, 1234)).await
    }
}

async fn recv(sock: Arc<RawSocket>, state: Arc<State>) -> Result<()> {
    let mut pkt = [0u8; 128];
    loop {
        let (n, from) = sock.recv_from(&mut pkt).await?;

        let now = Instant::now();
        let pkt = Ipv4Header::from_slice(&pkt[..n])?;

        if let (ip @ Ipv4Header { protocol: TCP, .. }, tail) = pkt {
            let src = IpAddr::V4(ip.source.into());
            let dst = IpAddr::V4(ip.destination.into());

            let pkt = TcpHeaderSlice::from_slice(tail)?;
            let dst = SocketAddr::new(dst, pkt.destination_port());
            let key = Key::TCP(dst, src);

            if let Some(tx) = state.sender(&key) {
                let _ = tx.send(Echo(from.ip(), now, true));
            }
        }
    }
}

const TCP: u8 = IpNumber::Tcp as u8;
