use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use std::sync::Arc;
use anyhow::Result;
use etherparse::{Ipv4Header, IpTrafficClass, TcpHeader};
use libc::{IPPROTO_TCP, c_int};
use log::{debug, error};
use raw_socket::tokio::prelude::*;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use crate::Bind;
use super::{probe::ProbeV4, reply::Reply};
use super::state::State;

pub struct Sock4 {
    sock:  Mutex<Arc<RawSocket>>,
    route: Mutex<UdpSocket>,
}

impl Sock4 {
    pub async fn new(bind: &Bind, state: Arc<State>) -> Result<Self> {
        let ipv4 = Domain::ipv4();
        let tcp  = Protocol::from(IPPROTO_TCP);

        let sock  = Arc::new(RawSocket::new(ipv4, Type::raw(), Some(tcp))?);
        let route = UdpSocket::bind(bind.sa4()).await?;

        sock.bind(bind.sa4()).await?;

        let enable: c_int = 6;
        sock.set_sockopt(Level::IPV4, Name::IPV4_HDRINCL, &enable)?;
        let rx = sock.clone();

        tokio::spawn(async move {
            match recv(rx, state).await {
                Ok(()) => debug!("recv finished"),
                Err(e) => error!("recv failed: {}", e),
            }
        });

        Ok(Self {
            sock:  Mutex::new(sock),
            route: Mutex::new(route),
        })
    }

    pub async fn send(&self, probe: &ProbeV4) -> Result<Instant> {
        let mut pkt = [0u8; 64];

        let pkt = probe.encode(&mut pkt)?;
        let dst = SocketAddr::V4(probe.dst);

        let sock = self.sock.lock().await;
        sock.send_to(&pkt, &dst).await?;

        Ok(Instant::now())
    }

    pub async fn source(&self, dst: IpAddr, port: u16) -> Result<IpAddr> {
        let route = self.route.lock().await;
        route.connect(SocketAddr::new(dst, port)).await?;
        Ok(route.local_addr()?.ip())
    }
}

async fn recv(sock: Arc<RawSocket>, state: Arc<State>) -> Result<()> {
    let mut pkt = [0u8; 128];
    loop {
        let (n, _from) = sock.recv_from(&mut pkt).await?;

        let now = Instant::now();
        let pkt = Ipv4Header::read_from_slice(&pkt[..n])?;

        if let (Ipv4Header { protocol: TCP, source: src, destination: dst, .. }, tail) = pkt {
            let (head, _tail) = TcpHeader::read_from_slice(tail)?;

            let src = SocketAddr::new(IpAddr::from(src), head.source_port);
            let dst = SocketAddr::new(IpAddr::from(dst), head.destination_port);

            if let Some(tx) = state.sender(dst, src) {
                match tx.send(Reply::new(head, now)).await {
                    Ok(()) => (),
                    Err(_) => (),
                }
            }
        }
    }
}

const TCP: u8 = IpTrafficClass::Tcp as u8;
