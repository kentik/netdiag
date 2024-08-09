use std::io::{IoSlice, IoSliceMut};
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use std::sync::Arc;
use anyhow::Result;
use etherparse::TcpHeader;
use libc::c_int;
use log::{debug, error};
use raw_socket::tokio::prelude::*;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use crate::{Bind, RouteSocket};
use super::probe::{Key, Probe};
use super::reply::Echo;
use super::state::State;

pub struct Sock6 {
    icmp:  Mutex<Arc<RawSocket>>,
    tcp:   Mutex<Arc<RawSocket>>,
    udp:   Mutex<Arc<RawSocket>>,
    route: Mutex<RouteSocket>,
    _join_set: JoinSet<()>,
}

impl Sock6 {
    pub async fn new(bind: &Bind, icmp: Arc<RawSocket>, state: Arc<State>) -> Result<Self> {
        let ipv6  = Domain::ipv6();
        let tcp   = Protocol::tcp();
        let udp   = Protocol::udp();

        let tcp   = Arc::new(RawSocket::new(ipv6, Type::raw(), Some(tcp))?);
        let udp   = Arc::new(RawSocket::new(ipv6, Type::raw(), Some(udp))?);
        let route = RouteSocket::new(bind.sa6()).await?;

        let offset: c_int = 16;
        let enable: c_int = 1;
        tcp.set_sockopt(Level::IPV6, Name::IPV6_CHECKSUM, &offset)?;
        tcp.set_sockopt(Level::IPV6, Name::IPV6_RECVPKTINFO, &enable)?;

        let offset: c_int = 6;
        udp.set_sockopt(Level::IPV6, Name::IPV6_CHECKSUM, &offset)?;
        udp.bind(bind.sa6()).await?;

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
        let mut dst = probe.dst();
        let mut ctl = [0u8; 64];
        let mut pkt = [0u8; 64];

        let pkt = probe.encode(&mut pkt, ttl)?;
        dst.set_port(0);

        let hops = CMsg::Ipv6HopLimit(ttl as c_int);
        let ctl  = CMsg::encode(&mut ctl, &[hops])?;
        let data = &[IoSlice::new(pkt)];

        match probe {
            Probe::ICMP(..) => self.icmp.lock().await,
            Probe::TCP(..)  => self.tcp.lock().await,
            Probe::UDP(..)  => self.udp.lock().await,
        }.send_msg(&dst, data, Some(ctl)).await?;

        Ok(Instant::now())
    }

    pub async fn source(&self, dst: IpAddr) -> Result<IpAddr> {
        let mut route = self.route.lock().await;
        route.source(SocketAddr::new(dst, 1234)).await
    }
}

async fn recv(sock: Arc<RawSocket>, state: Arc<State>) -> Result<()> {
    let mut pkt = [0u8; 64];
    let mut ctl = [0u8; 64];

    loop {
        let iovec = &[IoSliceMut::new(&mut pkt)];
        let (n, src) = sock.recv_msg(iovec, Some(&mut ctl)).await?;

        let now = Instant::now();
        let pkt = TcpHeader::from_slice(&pkt[..n]);
        let dst = CMsg::decode(&ctl).find_map(|msg| {
            match msg {
                CMsg::Ipv6PktInfo(info) => Some(info.addr().into()),
                _                       => None,
            }
        });

        if let (Ok((head, _tail)), Some(dst)) = (pkt, dst) {
            let src = src.ip();
            let dst = SocketAddr::new(dst, head.destination_port);
            let key = Key::TCP(dst, src);

            if let Some(tx) = state.sender(&key) {
                let _ = tx.send(Echo(src, now, true));
            }
        }
    }
}
