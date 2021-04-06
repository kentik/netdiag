use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;
use futures::ready;
use parking_lot::Mutex;
use tokio::sync::oneshot::{Receiver, Sender, channel, error::RecvError};
use super::probe::Token;

#[derive(Default)]
pub struct State(Mutex<HashMap<Token, Sender<Instant>>>);

pub struct Lease<'s> {
    state: &'s State,
    rx:    Receiver<Instant>,
    token: Token,
}

impl State {
    pub fn insert(&self, token: Token) -> Lease<'_> {
        let (tx, rx) = channel();
        self.0.lock().insert(token, tx);
        Lease::new(self, rx, token)
    }

    pub fn remove(&self, token: &Token) -> Option<Sender<Instant>> {
        self.0.lock().remove(token)
    }
}

impl<'s> Lease<'s> {
    fn new(state: &'s State, rx: Receiver<Instant>, token: Token) -> Self {
        Self { state, rx, token }
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        self.state.remove(&self.token);
    }
}

impl Future for Lease<'_> {
    type Output = Result<Instant, RecvError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match ready!(Pin::new(&mut self.rx).poll(cx)) {
            Ok(time) => Poll::Ready(Ok(time)),
            Err(e)   => Poll::Ready(Err(e)),
        }
    }
}
