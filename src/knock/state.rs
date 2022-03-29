use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use futures::ready;
use rand::prelude::*;
use rand::distributions::Uniform;
use parking_lot::Mutex;
use tokio::sync::oneshot::{Sender, Receiver, channel, error::RecvError};
use tokio::task;
use super::reply::Reply;

const PORT_MIN: u16 = 33434;
const PORT_MAX: u16 = 65407;

#[derive(Debug)]
pub struct State {
    range: Uniform<u16>,
    state: Mutex<HashMap<Key, Sender<Reply>>>,
}

#[derive(Debug, Hash, Eq, PartialEq)]
struct Key(SocketAddr, SocketAddr);

#[derive(Debug)]
pub struct Lease<'s> {
    state: &'s State,
    rx:    Receiver<Reply>,
    src:   SocketAddr,
    dst:   SocketAddr,
}

impl State {
    pub fn new() -> Self {
        Self {
            range: Uniform::new(PORT_MIN, PORT_MAX),
            state: Default::default(),
        }
    }

    pub async fn reserve(&self, src: IpAddr, dst: SocketAddr) -> Lease<'_> {
        let (tx, rx) = channel();

        loop {
            let port = thread_rng().sample(self.range);
            let src  = SocketAddr::new(src, port);
            let key  = Key(src, dst);

            if let Entry::Vacant(e) = self.state.lock().entry(key) {
                let lease = Lease { state: self, rx, src, dst };
                e.insert(tx);
                return lease;
            }

            task::yield_now().await;
        }
    }

    pub fn remove(&self, src: SocketAddr, dst: SocketAddr) -> Option<Sender<Reply>> {
        self.state.lock().remove(&Key(src, dst))
    }
}

impl Lease<'_> {
    pub fn src(&self) -> SocketAddr {
        self.src
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        self.state.remove(self.src, self.dst);
    }
}

impl Future for Lease<'_> {
    type Output = Result<Reply, RecvError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match ready!(Pin::new(&mut self.rx).poll(cx)) {
            Ok(reply) => Poll::Ready(Ok(reply)),
            Err(e)    => Poll::Ready(Err(e)),
        }
    }
}
