use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use rand::prelude::*;
use rand::distributions::Uniform;
use parking_lot::Mutex;
use tokio::sync::mpsc::{Sender, Receiver, channel};
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

    pub async fn reserve(&self, src: IpAddr, dst: SocketAddr) -> (Lease<'_>, Receiver<Reply>) {
        let (tx, rx) = channel(10);

        loop {
            let port = thread_rng().sample(self.range);
            let src  = SocketAddr::new(src, port);
            let key  = Key(src, dst);

            if let Entry::Vacant(e) = self.state.lock().entry(key) {
                let lease = Lease::new(self, src, dst);
                e.insert(tx);
                return (lease, rx);
            }

            task::yield_now().await;
        }
    }

    pub fn sender(&self, src: SocketAddr, dst: SocketAddr) -> Option<Sender<Reply>> {
        self.state.lock().get(&Key(src, dst)).map(Sender::clone)
    }

    fn release(&self, key: &Key) {
        self.state.lock().remove(key);
    }
}

impl<'s> Lease<'s> {
    fn new(state: &'s State, src: SocketAddr, dst: SocketAddr) -> Self {
        Self { state, src, dst }
    }
}

impl Deref for Lease<'_> {
    type Target = SocketAddr;

    fn deref(&self) -> &Self::Target {
        &self.src
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        self.state.release(&Key(self.src, self.dst))
    }
}
