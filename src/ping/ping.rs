use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use futures::{stream::try_unfold, Stream, StreamExt};
use log::error;
use rand::random;
use tokio::{sync::broadcast, time::timeout};

use super::{probe::Probe, sock4::Sock4, sock6::Sock6, state::State};
use crate::Bind;

#[derive(Debug)]
pub struct Ping {
    pub addr: IpAddr,
    pub count: usize,
    pub expiry: Duration,
}

pub struct Pinger {
    sock4: Sock4,
    sock6: Sock6,
    state: Arc<State>,
    shutdown: broadcast::Sender<()>,
}

impl Pinger {
    pub async fn new(bind: &Bind) -> Result<Self> {
        let state = Arc::new(State::default());

        let (notify_shutdown, _) = broadcast::channel(1);

        let sock4 = Sock4::new(bind, state.clone(), notify_shutdown.subscribe()).await?;
        let sock6 = Sock6::new(bind, state.clone(), notify_shutdown.subscribe()).await?;

        Ok(Self {
            sock4,
            sock6,
            state,
            shutdown: notify_shutdown,
        })
    }

    pub fn ping(&self, ping: &Ping) -> impl Stream<Item = Result<Option<Duration>>> + '_ {
        let Ping {
            addr,
            count,
            expiry,
        } = *ping;

        try_unfold(0, move |seq| async move {
            let ident = random();
            let probe = Probe::new(addr, ident, seq);
            let rtt = self.probe(&probe, expiry).await?;
            Ok(Some((rtt, (seq.wrapping_add(1)))))
        })
        .take(count)
    }

    async fn probe(&self, probe: &Probe, expiry: Duration) -> Result<Option<Duration>> {
        let rx = self.state.insert(probe.token);
        let sent = self.send(probe).await?;

        Ok(match timeout(expiry, rx).await {
            Ok(r) => Some(r?.saturating_duration_since(sent)),
            Err(_) => None,
        })
    }

    async fn send(&self, probe: &Probe) -> Result<Instant> {
        match probe.addr {
            IpAddr::V4(_) => self.sock4.send(probe).await,
            IpAddr::V6(_) => self.sock6.send(probe).await,
        }
    }
}

impl Drop for Pinger {
    fn drop(&mut self) {
        if let Err(e) = self.shutdown.send(()) {
            error!("background task shutdown failed: {}", e);
        }
    }
}
