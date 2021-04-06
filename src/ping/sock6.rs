use std::convert::{TryFrom, TryInto};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use anyhow::Result;
use log::{debug, error};
use raw_socket::{Domain, Type, Protocol};
use raw_socket::tokio::RawSocket;
use tokio::sync::Mutex;
use crate::Bind;
use crate::icmp::IcmpV6Packet;
use super::probe::Probe;
use super::state::State;

pub struct Sock6 {
    sock: Mutex<Arc<RawSocket>>
}

impl Sock6 {
    pub async fn new(bind: &Bind, state: Arc<State>) -> Result<Self> {
        let raw   = Type::raw();
        let icmp6 = Protocol::icmpv6();

        let sock = Arc::new(RawSocket::new(Domain::ipv6(), raw, Some(icmp6))?);
        sock.bind(bind.sa6()).await?;
        let rx = sock.clone();

        tokio::spawn(async move {
            match recv(rx, state).await {
                Ok(()) => debug!("recv finished"),
                Err(e) => error!("recv failed: {}", e),
            }
        });

        Ok(Self { sock: Mutex::new(sock) })
    }

    pub async fn send(&self, probe: &Probe) -> Result<Instant> {
        let mut pkt = [0u8; 64];

        let pkt  = probe.encode(&mut pkt)?;
        let addr = SocketAddr::new(probe.addr, 0);
        let sock = self.sock.lock().await;
        sock.send_to(&pkt, &addr).await?;

        Ok(Instant::now())
    }
}

async fn recv(sock: Arc<RawSocket>, state: Arc<State>) -> Result<()> {
    let mut pkt = [0u8; 64];
    loop {
        let (n, _) = sock.recv_from(&mut pkt).await?;

        let now = Instant::now();
        let pkt = IcmpV6Packet::try_from(&pkt[..n])?;

        if let IcmpV6Packet::EchoReply(echo) = pkt {
            if let Ok(token) = echo.data.try_into() {
                if let Some(tx) = state.remove(&token) {
                    let _ = tx.send(now);
                }
            }
        }
    }
}
