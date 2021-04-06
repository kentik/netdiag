use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use rand::prelude::*;
use rand::distributions::Uniform;
use parking_lot::Mutex;
use tokio::sync::oneshot::Sender;
use tokio::task;
use super::probe::{Protocol, Key, PORT_MIN, PORT_MAX};
use super::reply::Echo;

#[derive(Debug)]
pub struct State {
    range:  Uniform<u16>,
    tcp:    Mutex<HashMap<SocketAddr, ()>>,
    udp:    Mutex<HashMap<SocketAddr, ()>>,
    state:  Mutex<HashMap<Key, Sender<Echo>>>,
}

#[derive(Debug)]
pub struct Lease<'s> {
    state: &'s State,
    proto: Protocol,
    addr:  SocketAddr,
}

impl State {
    pub fn new() -> Self {
        Self {
            range:  Uniform::new(PORT_MIN, PORT_MAX),
            tcp:    Default::default(),
            udp:    Default::default(),
            state:  Default::default(),
        }
    }

    pub async fn reserve(&self, proto: Protocol, src: IpAddr) -> Lease<'_> {
        let map = match proto {
            Protocol::TCP(..) => &self.tcp,
            Protocol::UDP(..) => &self.udp,
        };

        loop {
            let port = thread_rng().sample(self.range);
            let src  = SocketAddr::new(src, port);

            if let Entry::Vacant(e) = map.lock().entry(src) {
                e.insert(());
                return Lease::new(self, proto, src)
            }

            task::yield_now().await;
        }
    }

    pub fn release(&self, proto: Protocol, src: &SocketAddr) {
        match proto {
            Protocol::TCP(..) => self.tcp.lock().remove(src),
            Protocol::UDP(..) => self.udp.lock().remove(src),
        };
    }

    pub fn insert(&self, key: Key, tx: Sender<Echo>) {
        self.state.lock().insert(key, tx);
    }

    pub fn remove(&self, key: &Key) -> Option<Sender<Echo>> {
        self.state.lock().remove(key)
    }
}

impl<'s> Lease<'s> {
    fn new(state: &'s State, proto: Protocol, addr: SocketAddr) -> Self {
        Self { state, proto, addr }
    }
}

impl Deref for Lease<'_> {
    type Target = SocketAddr;

    fn deref(&self) -> &Self::Target {
        &self.addr
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        self.state.release(self.proto, &self.addr);
    }
}
