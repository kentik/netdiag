use std::convert::TryFrom;
use std::future::Future;
use std::sync::Arc;
use std::time::Instant;
use anyhow::Result;
use etherparse::{IpTrafficClass, Ipv4Header};
use log::{debug, error};
use raw_socket::tokio::prelude::*;
use crate::icmp::{icmp4, icmp6, IcmpV4Packet, IcmpV6Packet};
use super::probe::Probe;
use super::reply::Echo;
use super::state::State;

pub async fn recv(state: Arc<State>) -> Result<()> {
    let ipv4 = Domain::ipv4();
    let ipv6 = Domain::ipv6();

    let icmp4 = RawSocket::new(ipv4, Type::raw(), Some(Protocol::icmpv4()))?;
    let icmp6 = RawSocket::new(ipv6, Type::raw(), Some(Protocol::icmpv6()))?;

    spawn("recv4", recv4(icmp4, state.clone()));
    spawn("recv6", recv6(icmp6, state.clone()));

    Ok(())
}

async fn recv4(sock: RawSocket, state: Arc<State>) -> Result<()> {
    let mut pkt = [0u8; 128];
    loop {
        let (n, from) = sock.recv_from(&mut pkt).await?;

        let now = Instant::now();
        let pkt = Ipv4Header::read_from_slice(&pkt[..n])?;

        if let (Ipv4Header { protocol: ICMP, .. }, tail) = pkt {
            let icmp = IcmpV4Packet::try_from(tail)?;

            if let IcmpV4Packet::TimeExceeded(pkt) = icmp {
                if let Ok(probe) = Probe::decode4(pkt) {
                    if let Some(tx) = state.remove(&probe.key()) {
                        let _ = tx.send(Echo(from.ip(), now, false));
                    }
                }
            } else if let IcmpV4Packet::Unreachable(what) = icmp {
                let pkt = match what {
                    icmp4::Unreachable::Net(pkt)      => pkt,
                    icmp4::Unreachable::Host(pkt)     => pkt,
                    icmp4::Unreachable::Protocol(pkt) => pkt,
                    icmp4::Unreachable::Port(pkt)     => pkt,
                    icmp4::Unreachable::Other(_, pkt) => pkt,
                };

                if let Ok(probe) = Probe::decode4(pkt) {
                    if let Some(tx) = state.remove(&probe.key()) {
                        let _ = tx.send(Echo(from.ip(), now, true));
                    }
                }
            }
        }
    }
}

async fn recv6(sock: RawSocket, state: Arc<State>) -> Result<()> {
    let mut pkt = [0u8; 64];
    loop {
        let (n, from) = sock.recv_from(&mut pkt).await?;

        let now = Instant::now();
        let pkt = IcmpV6Packet::try_from(&pkt[..n])?;

        if let IcmpV6Packet::HopLimitExceeded(pkt) = pkt {
            if let Ok(probe) = Probe::decode6(pkt) {
                if let Some(tx) = state.remove(&probe.key()) {
                    let _ = tx.send(Echo(from.ip(), now, false));
                }
            }
        } else if let IcmpV6Packet::Unreachable(what) = pkt {
            let pkt = match what {
                icmp6::Unreachable::Address(pkt)  => pkt,
                icmp6::Unreachable::Port(pkt)     => pkt,
                icmp6::Unreachable::Other(_, pkt) => pkt,
            };

            if let Ok(probe) = Probe::decode6(pkt) {
                if let Some(tx) = state.remove(&probe.key()) {
                    let _ = tx.send(Echo(from.ip(), now, true));
                }
            }
        }
    }
}

fn spawn<F: Future<Output = Result<()>> + Send + 'static>(name: &'static str, future: F) {
    tokio::spawn(async move {
        match future.await {
            Ok(()) => debug!("{} finished", name),
            Err(e) => error!("{} failed: {}", name, e),
        }
    });
}

const ICMP: u8 = IpTrafficClass::Icmp as u8;
