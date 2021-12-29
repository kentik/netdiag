use anyhow::Result;
use log::{debug, error};
use raw_socket::{tokio::RawSocket, Domain, Protocol, Type};
use std::{
    convert::{TryFrom, TryInto},
    net::SocketAddr,
    sync::Arc,
    time::Instant,
};
use tokio::sync::{broadcast, Mutex};

use super::{probe::Probe, state::State};
use crate::{icmp::IcmpV6Packet, Bind};

pub struct Sock6 {
    sock: Mutex<Arc<RawSocket>>,
}

impl Sock6 {
    pub async fn new(
        bind: &Bind,
        state: Arc<State>,
        notify: broadcast::Receiver<()>,
    ) -> Result<Self> {
        let raw = Type::raw();
        let icmp6 = Protocol::icmpv6();

        let sock = Arc::new(RawSocket::new(Domain::ipv6(), raw, Some(icmp6))?);
        sock.bind(bind.sa6()).await?;
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
    let mut pkt = [0u8; 64];
    loop {
        tokio::select! {
            result = sock.recv_from(&mut pkt) => {
                let (n, _) = result?;

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
            _ = shutdown.recv() => {
                break;
            }
        }
    }
    Ok(())
}
