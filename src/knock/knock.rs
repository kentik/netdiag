use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::Result;
use futures::{Stream, StreamExt};
use futures::stream::try_unfold;
use rand::prelude::*;
use tokio::sync::mpsc::Receiver;
use tokio::time::timeout;
use crate::Bind;
use super::{probe::Probe, reply::Reply};
use super::{sock4::Sock4, sock6::Sock6};
use super::state::State;

#[derive(Debug)]
pub struct Knock {
    pub addr:   IpAddr,
    pub port:   u16,
    pub count:  usize,
    pub expiry: Duration,
}

pub struct Knocker {
    sock4: Sock4,
    sock6: Sock6,
    state: Arc<State>,
}

impl Knocker {
    pub async fn new(bind: &Bind) -> Result<Self> {
        let state = Arc::new(State::new());

        let sock4 = Sock4::new(bind, state.clone()).await?;
        let sock6 = Sock6::new(bind, state.clone()).await?;

        Ok(Self { sock4, sock6, state })
    }

    pub async fn knock(&self, knock: &Knock) -> Result<impl Stream<Item = Result<Option<Duration>>> + '_> {
        let Knock { addr, port, count, expiry } = *knock;

        let dst = SocketAddr::new(addr, port);
        let src = self.source(addr, port).await?;
        let (src, rx) = self.state.reserve(src, dst).await;

        Ok(try_unfold((src, rx), move |(src, mut rx)| async move {
            let seq   = random();
            let probe = Probe::new(*src, dst, seq)?;
            let rtt   = self.probe(&probe, &mut rx, expiry).await?;
            Ok(Some((rtt, (src, rx))))
        }).take(count))
    }

    async fn probe(&self, probe: &Probe, rx: &mut Receiver<Reply>, expiry: Duration) -> Result<Option<Duration>> {
        let mut retries = 1;

        while retries > 0 {
            let sent  = self.send(probe).await?;
            let reply = timeout(expiry, rx.recv());

            if let Ok(Some(Reply { head, when })) = reply.await {
                if head.syn && head.ack {
                    if head.acknowledgment_number == probe.seq() + 1 {
                        return Ok(Some(when.saturating_duration_since(sent)))
                    }
                }
            }

            retries -= 1;
        }

        Ok(None)
    }

    async fn send(&self, probe: &Probe) -> Result<Instant> {
        match probe {
            Probe::V4(v4) => self.sock4.send(v4).await,
            Probe::V6(v6) => self.sock6.send(v6).await,
        }
    }

    async fn source(&self, dst: IpAddr, port: u16) -> Result<IpAddr> {
        match dst {
            IpAddr::V4(..) => self.sock4.source(dst, port).await,
            IpAddr::V6(..) => self.sock6.source(dst, port).await,
        }
    }
}
