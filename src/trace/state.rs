use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::IpAddr;
use std::ops::Deref;
use rand::prelude::*;
use rand::distributions::Uniform;
use parking_lot::Mutex;
use tokio::sync::broadcast::{Receiver, Sender, channel};
use tokio::task;
use super::probe::{Key, Probes, Protocol, PORT_MIN, PORT_MAX};
use super::reply::Echo;

#[derive(Debug)]
pub struct State {
    range: Uniform<u16>,
    state: Mutex<HashMap<Key, Sender<Echo>>>,
}

#[derive(Debug)]
pub struct Lease<'s> {
    state:  &'s State,
    probes: Probes,
}

impl State {
    pub fn new() -> Self {
        Self {
            range: Uniform::new(PORT_MIN, PORT_MAX),
            state: Default::default(),
        }
    }

    pub async fn reserve(&self, proto: Protocol, src: IpAddr, dst: IpAddr) -> Lease<'_> {
        let (tx, _) = channel(10);

        loop {
            let value  = thread_rng().sample(self.range);
            let probes = Probes::new(proto, src, dst, value);
            let key    = probes.key();

            if let Entry::Vacant(e) = self.state.lock().entry(key) {
                e.insert(tx);
                return Lease::new(self, probes);
            }

            task::yield_now().await;
        }
    }

    pub fn sender(&self, key: &Key) -> Option<Sender<Echo>> {
        self.state.lock().get(key).map(Sender::clone)
    }

    pub fn receiver(&self, key: &Key) -> Option<Receiver<Echo>> {
        self.state.lock().get(key).map(Sender::subscribe)
    }

    pub fn release(&self, key: &Key) {
        self.state.lock().remove(key);
    }
}

impl<'s> Lease<'s> {
    fn new(state: &'s State, probes: Probes) -> Self {
        Self { state, probes }
    }
}

impl Deref for Lease<'_> {
    type Target = Probes;

    fn deref(&self) -> &Self::Target {
        &self.probes
    }
 }

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        let key = self.probes.key();
        self.state.release(&key);
    }
}
