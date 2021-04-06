use std::io::IoSliceMut;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use std::sync::Arc;
use anyhow::Result;
use etherparse::TcpHeader;
use libc::{IPPROTO_TCP, c_int};
use log::{debug, error};
use raw_socket::tokio::prelude::*;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use crate::Bind;
use super::{probe::ProbeV6, reply::Reply};
use super::state::State;

pub struct Sock6 {
    sock:  Mutex<Arc<RawSocket>>,
    route: Mutex<UdpSocket>,
}

impl Sock6 {
    pub async fn new(bind: &Bind, state: Arc<State>) -> Result<Self> {
        let ipv6 = Domain::ipv6();
        let tcp  = Protocol::from(IPPROTO_TCP);

        let sock  = Arc::new(RawSocket::new(ipv6, Type::raw(), Some(tcp))?);
        let route = UdpSocket::bind(bind.sa6()).await?;

        sock.bind(bind.sa6()).await?;

        let offset: c_int = 16;
        let enable: c_int = 1;
        sock.set_sockopt(Level::IPV6, Name::IPV6_CHECKSUM, &offset)?;
        sock.set_sockopt(Level::IPV6, Name::IPV6_RECVPKTINFO, &enable)?;
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

    pub async fn send(&self, probe: &ProbeV6) -> Result<Instant> {
        let mut dst = probe.dst;
        let mut pkt = [0u8; 64];

        let pkt = probe.encode(&mut pkt)?;
        dst.set_port(0);
        let dst = SocketAddr::V6(dst);

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
    let mut pkt = [0u8; 64];
    let mut ctl = [0u8; 64];

    loop {
        let iovec = &[IoSliceMut::new(&mut pkt)];
        let (n, src) = sock.recv_msg(iovec, Some(&mut ctl)).await?;

        let now = Instant::now();
        let pkt = TcpHeader::read_from_slice(&pkt[..n]);
        let dst = CMsg::decode(&ctl).find_map(|msg| {
            match msg {
                CMsg::Ipv6PktInfo(info) => Some(info.addr().into()),
                _                       => None,
            }
        });

        if let (Ok((head, _tail)), Some(dst)) = (pkt, dst) {
            let src = SocketAddr::new(src.ip(), head.source_port);
            let dst = SocketAddr::new(dst, head.destination_port);

            if let Some(tx) = state.sender(dst, src) {
                match tx.send(Reply::new(head, now)).await {
                    Ok(()) => (),
                    Err(_) => (),
                }
            }
        }
    }
}
