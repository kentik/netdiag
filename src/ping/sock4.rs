use super::probe::Probe;
use super::state::State;
use crate::icmp::icmp4::checksum;
use crate::icmp::IcmpV4Packet;
use crate::Bind;
use anyhow::Result;
use etherparse::{IpNumber, Ipv4Header};
use log::{debug, error};
use raw_socket::tokio::RawSocket;
use raw_socket::{Domain, Protocol, Type};
use std::convert::{TryFrom, TryInto};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{broadcast, Mutex};

pub struct Sock4 {
    sock: Mutex<Arc<RawSocket>>,
}

impl Sock4 {
    pub async fn new(
        bind: &Bind,
        state: Arc<State>,
        notify: broadcast::Receiver<()>,
    ) -> Result<Self> {
        let raw = Type::raw();
        let icmp4 = Protocol::icmpv4();

        let sock = Arc::new(RawSocket::new(Domain::ipv4(), raw, Some(icmp4))?);
        sock.bind(bind.sa4()).await?;
        let rx = sock.clone();

        tokio::spawn(async move {
            match recv(rx, state, notify).await {
                Ok(()) => debug!("recv finished"),
                Err(e) => error!("recv failed: {}", e),
            }
        });

        Ok(Self {
            sock: Mutex::new(sock),
        })
    }

    pub async fn send(&self, probe: &Probe) -> Result<Instant> {
        let mut pkt = [0u8; 64];

        let pkt = probe.encode(&mut pkt)?;
        let cksum = checksum(pkt).to_be_bytes();
        pkt[2..4].copy_from_slice(&cksum);

        let addr = SocketAddr::new(probe.addr, 0);
        let sock = self.sock.lock().await;
        sock.send_to(pkt, &addr).await?;

        Ok(Instant::now())
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
                let (n, _) = result?;

                let now = Instant::now();
                let pkt = Ipv4Header::from_slice(&pkt[..n])?;

                if let (Ipv4Header { protocol: ICMP4, .. }, tail) = pkt {
                    if let IcmpV4Packet::EchoReply(echo) = IcmpV4Packet::try_from(tail)? {
                        if let Ok(token) = echo.data.try_into() {
                            if let Some(tx) = state.remove(&token) {
                                let _ = tx.send(now);
                            }
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

const ICMP4: u8 = IpNumber::Icmp as u8;
