use std::time::Duration;
use anyhow::Result;
use futures::{Stream, StreamExt, TryStreamExt};
use futures::stream::unfold;
use super::probe::Probe;
use super::reply::Node;
use super::trace::Tracer;

pub struct Route<'t> {
    tracer: &'t Tracer,
    expiry: Duration,
}

impl<'t> Route<'t> {
    pub fn new(tracer: &'t Tracer, expiry: Duration) -> Route<'t> {
        Route { tracer, expiry }
    }

    pub fn trace(&'t self, probe: Probe, probes: usize) -> impl Stream<Item = Result<Vec<Node>>> + 't {
        unfold((self, probe, probes, 1), |(route, mut probe, probes, ttl)| async move {
            let stream = route.probe(&mut probe, ttl).take(probes);
            let result = stream.try_collect::<Vec<_>>().await;
            Some((result, (route, probe, probes, ttl + 1)))
        })
    }

    pub fn probe(&'t self, probe: &'t mut Probe, ttl: u8) -> impl Stream<Item = Result<Node>> + 't {
        unfold((self, probe, ttl), |(route, probe, ttl)| async move {
            let Route { tracer, expiry, .. } = route;
            let result = tracer.probe(probe, ttl, *expiry).await;
            probe.increment();
            Some((result, (route, probe, ttl)))
        })
    }
}
