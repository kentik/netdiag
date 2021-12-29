use super::icmp;
use super::probe::{Probe, Protocol, ICMP, TCP, UDP};
use super::reply::{Echo, Node};
use super::state::{Lease, State};
use super::{sock4::Sock4, sock6::Sock6};
use crate::Bind;
use anyhow::Result;
use futures::future;
use futures::stream::try_unfold;
use futures::{Stream, StreamExt, TryStreamExt};
use log::error;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tokio::time::timeout;

#[derive(Debug)]
pub struct Trace {
    pub proto: Protocol,
    pub addr: IpAddr,
    pub probes: usize,
    pub limit: usize,
    pub expiry: Duration,
}

pub struct Tracer {
    sock4: Sock4,
    sock6: Sock6,
    state: Arc<State>,
    shutdown: broadcast::Sender<()>,
}

impl Tracer {
    pub async fn new(bind: &Bind) -> Result<Self> {
        let state = Arc::new(State::new());

        let (notify_shutdown, _) = broadcast::channel(1);

        let (icmp4, icmp6) = icmp::exec(bind, &state).await?;
        let sock4 = Sock4::new(bind, icmp4, state.clone(), notify_shutdown.subscribe()).await?;
        let sock6 = Sock6::new(bind, icmp6, state.clone(), notify_shutdown.subscribe()).await?;

        Ok(Self {
            sock4,
            sock6,
            state,
            shutdown: notify_shutdown,
        })
    }

    pub async fn route(&self, trace: Trace) -> Result<Vec<Vec<Node>>> {
        let Trace {
            proto,
            addr,
            probes,
            limit,
            expiry,
        } = trace;

        let source = self.reserve(proto, addr).await?;

        let mut probe = source.probe()?;
        let mut done = false;

        Ok(self
            .trace(&mut probe, probes, expiry)
            .take_while(|result| {
                let last = done;
                if let Ok(nodes) = result {
                    done = nodes.iter().any(|node| match node {
                        Node::Node(_, ip, _, done) => *done || ip == &addr,
                        Node::None(_) => false,
                    });
                }
                future::ready(!last)
            })
            .take(limit)
            .try_collect()
            .await?)
    }

    pub fn trace<'a>(
        &'a self,
        probe: &'a mut Probe,
        count: usize,
        expiry: Duration,
    ) -> impl Stream<Item = Result<Vec<Node>>> + 'a {
        try_unfold((probe, 1), move |(probe, ttl)| async move {
            let stream = self.probe(probe, ttl, expiry);
            let result = stream.take(count).try_collect().await?;
            Ok(Some((result, (probe, ttl + 1))))
        })
    }

    pub fn probe<'a>(
        &'a self,
        probe: &'a mut Probe,
        ttl: u8,
        expiry: Duration,
    ) -> impl Stream<Item = Result<Node>> + 'a {
        try_unfold(probe, move |probe| async move {
            let sent = self.send(probe, ttl).await?;
            let recv = self.recv(probe);
            let echo = timeout(expiry, recv).await;

            probe.increment();

            if let Ok(Some(Echo(addr, when, last))) = echo {
                let rtt = when.saturating_duration_since(sent);
                let node = Node::Node(ttl, addr, rtt, last);
                return Ok(Some((node, probe)));
            }

            Ok(Some((Node::None(ttl), probe)))
        })
    }

    pub async fn reserve(&self, proto: Protocol, addr: IpAddr) -> Result<Lease<'_>> {
        let src = self.source(addr).await?;
        Ok(self.state.reserve(proto, src, addr).await)
    }

    async fn send(&self, probe: &Probe, ttl: u8) -> Result<Instant> {
        match probe {
            Probe::ICMP(ICMP::V4(_)) => self.sock4.send(probe, ttl).await,
            Probe::ICMP(ICMP::V6(_)) => self.sock6.send(probe, ttl).await,
            Probe::TCP(TCP::V4(_)) => self.sock4.send(probe, ttl).await,
            Probe::TCP(TCP::V6(_)) => self.sock6.send(probe, ttl).await,
            Probe::UDP(UDP::V4(_)) => self.sock4.send(probe, ttl).await,
            Probe::UDP(UDP::V6(_)) => self.sock6.send(probe, ttl).await,
        }
    }

    async fn recv(&self, probe: &Probe) -> Option<Echo> {
        self.state.receiver(&probe.key())?.recv().await.ok()
    }

    async fn source(&self, dst: IpAddr) -> Result<IpAddr> {
        match dst {
            IpAddr::V4(..) => self.sock4.source(dst).await,
            IpAddr::V6(..) => self.sock6.source(dst).await,
        }
    }
}

impl Drop for Tracer {
    fn drop(&mut self) {
        if let Err(e) = self.shutdown.send(()) {
            error!("background task shutdown failed: {}", e);
        }
    }
}
