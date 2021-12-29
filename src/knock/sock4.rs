use super::state::State;
use super::{probe::ProbeV4, reply::Reply};
use crate::{Bind, RouteSocket};
use anyhow::Result;
use etherparse::{IpNumber, Ipv4Header, TcpHeader};
use libc::{c_int, IPPROTO_TCP};
use log::{debug, error};
use raw_socket::tokio::prelude::*;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::broadcast;
use tokio::sync::Mutex;

pub struct Sock4 {
    sock: Mutex<Arc<RawSocket>>,
    route: Mutex<RouteSocket>,
}

impl Sock4 {
    pub async fn new(
        bind: &Bind,
        state: Arc<State>,
        shutdown: broadcast::Receiver<()>,
    ) -> Result<Self> {
        let ipv4 = Domain::ipv4();
        let tcp = Protocol::from(IPPROTO_TCP);

        let sock = Arc::new(RawSocket::new(ipv4, Type::raw(), Some(tcp))?);
        let route = RouteSocket::new(bind.sa4()).await?;

        sock.bind(bind.sa4()).await?;

        let enable: c_int = 6;
        sock.set_sockopt(Level::IPV4, Name::IPV4_HDRINCL, &enable)?;
        let rx = sock.clone();

        tokio::spawn(async move {
            match recv(rx, state, shutdown).await {
                Ok(()) => debug!("recv finished"),
                Err(e) => error!("recv failed: {}", e),
            }
        });

        Ok(Self {
            sock: Mutex::new(sock),
            route: Mutex::new(route),
        })
    }

    pub async fn send(&self, probe: &ProbeV4) -> Result<Instant> {
        let mut pkt = [0u8; 64];

        let pkt = probe.encode(&mut pkt)?;
        let dst = SocketAddr::V4(probe.dst);

        let sock = self.sock.lock().await;
        sock.send_to(pkt, &dst).await?;

        Ok(Instant::now())
    }

    pub async fn source(&self, dst: IpAddr, port: u16) -> Result<IpAddr> {
        let mut route = self.route.lock().await;
        route.source(SocketAddr::new(dst, port)).await
    }
}

async fn recv(
    sock: Arc<RawSocket>,
    state: Arc<State>,
    mut shutdown: broadcast::Receiver<()>,
) -> Result<()> {
    let mut pkt = [0u8; 128];
    loop {
        tokio::select! {
            result = sock.recv_from(&mut pkt) => {
                let (n, _from) = result?;

                let now = Instant::now();
                let pkt = Ipv4Header::from_slice(&pkt[..n])?;

                if let (
                    Ipv4Header {
                        protocol: TCP,
                        source: src,
                        destination: dst,
                        ..
                    },
                    tail,
                ) = pkt
                {
                    let (head, _tail) = TcpHeader::from_slice(tail)?;

                    let src = SocketAddr::new(IpAddr::from(src), head.source_port);
                    let dst = SocketAddr::new(IpAddr::from(dst), head.destination_port);

                    if let Some(tx) = state.sender(dst, src) {
                        if let Err(e) = tx.send(Reply::new(head, now)).await {
                            error!("{}", e);
                        }
                    }
                }
            }
            _ = shutdown.recv() => {
                break;
            }
        }
    }
    Ok(())
}

const TCP: u8 = IpNumber::Tcp as u8;
