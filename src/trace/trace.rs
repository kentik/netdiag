use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::Result;
use futures::future;
use futures::{StreamExt, TryStreamExt};
use tokio::sync::oneshot::channel;
use tokio::time::timeout;
use crate::Bind;
use super::probe::{Probe, Protocol, TCP, UDP};
use super::{reply::{Node, Reply}, route::Route};
use super::{sock4::Sock4, sock6::Sock6};
use super::state::State;
use super::icmp;

#[derive(Debug)]
pub struct Trace {
    pub proto:  Protocol,
    pub addr:   IpAddr,
    pub probes: usize,
    pub limit:  usize,
    pub expiry: Duration,
}

pub struct Tracer {
    sock4: Sock4,
    sock6: Sock6,
    state: Arc<State>,
}

impl Tracer {
    pub async fn new(bind: &Bind) -> Result<Self> {
        let state = Arc::new(State::new());

        icmp::recv(state.clone()).await?;
        let sock4 = Sock4::new(bind, state.clone()).await?;
        let sock6 = Sock6::new(bind, state.clone()).await?;

        Ok(Self { sock4, sock6, state })
    }

    pub async fn route(&self, trace: Trace) -> Result<Vec<Vec<Node>>> {
        let Trace { proto, addr, probes, limit, expiry } = trace;

        let src = self.source(addr).await?;
        let src = self.state.reserve(proto, src).await;
        let probe = Probe::new(proto, *src, addr)?;
        let route = Route::new(self, expiry);

        let mut done = false;
        Ok(route.trace(probe, probes).take_while(|result| {
            let last = done;
            if let Ok(nodes) = result {
                done = nodes.iter().any(|node| {
                    match node {
                        Node::Node(_, ip, _, done) => *done || ip == &addr,
                        Node::None(_)              => false,
                    }
                });
            }
            future::ready(!last)
        }).take(limit).try_collect().await?)
    }

    pub async fn probe(&self, probe: &Probe, ttl: u8, expiry: Duration) -> Result<Node> {
        let state = self.state.clone();

        let (tx, rx) = channel();
        state.insert(probe.key(), tx);

        let sent = self.send(probe, ttl).await?;
        let echo = timeout(expiry, rx);
        let key  = probe.key();
        Reply::new(echo, sent, state, key, ttl).await
    }

    pub async fn send(&self, probe: &Probe, ttl: u8) -> Result<Instant> {
        match probe {
            Probe::TCP(TCP::V4(_)) => self.sock4.send(probe, ttl).await,
            Probe::TCP(TCP::V6(_)) => self.sock6.send(probe, ttl).await,
            Probe::UDP(UDP::V4(_)) => self.sock4.send(probe, ttl).await,
            Probe::UDP(UDP::V6(_)) => self.sock6.send(probe, ttl).await,
        }
    }

    pub async fn source(&self, dst: IpAddr) -> Result<IpAddr> {
        match dst {
            IpAddr::V4(..) => self.sock4.source(dst).await,
            IpAddr::V6(..) => self.sock6.source(dst).await,
        }
    }
}
