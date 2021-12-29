use super::probe::{Key, Probe};
use super::reply::Echo;
use super::state::State;
use crate::icmp::{icmp4, icmp6, IcmpV4Packet, IcmpV6Packet};
use crate::Bind;
use anyhow::Result;
use etherparse::{IpNumber, Ipv4Header};
use libc::c_int;
use log::{debug, error};
use raw_socket::tokio::prelude::*;
use std::convert::TryFrom;
use std::future::Future;
use std::io::IoSliceMut;
use std::sync::Arc;
use std::time::Instant;

pub async fn exec(bind: &Bind, state: &Arc<State>) -> Result<(Arc<RawSocket>, Arc<RawSocket>)> {
    let ipv4 = Domain::ipv4();
    let ipv6 = Domain::ipv6();
    let icmp4 = Protocol::icmpv4();
    let icmp6 = Protocol::icmpv6();

    let icmp4 = Arc::new(RawSocket::new(ipv4, Type::raw(), Some(icmp4))?);
    let icmp6 = Arc::new(RawSocket::new(ipv6, Type::raw(), Some(icmp6))?);

    icmp4.bind(bind.sa4()).await?;
    icmp6.bind(bind.sa6()).await?;

    let enable: c_int = 1;
    icmp4.set_sockopt(Level::IPV4, Name::IPV4_HDRINCL, &enable)?;
    icmp6.set_sockopt(Level::IPV6, Name::IPV6_RECVPKTINFO, &enable)?;

    spawn("recv4", recv4(icmp4.clone(), state.clone()));
    spawn("recv6", recv6(icmp6.clone(), state.clone()));

    Ok((icmp4, icmp6))
}

async fn recv4(sock: Arc<RawSocket>, state: Arc<State>) -> Result<()> {
    let mut pkt = [0u8; 128];
    loop {
        let (n, from) = sock.recv_from(&mut pkt).await?;

        let now = Instant::now();
        let pkt = Ipv4Header::from_slice(&pkt[..n])?;

        if let (ip @ Ipv4Header { protocol: ICMP, .. }, tail) = pkt {
            let icmp = IcmpV4Packet::try_from(tail)?;

            if let IcmpV4Packet::TimeExceeded(pkt) = icmp {
                if let Ok(key) = Probe::decode4(pkt) {
                    if let Some(tx) = state.sender(&key) {
                        let _ = tx.send(Echo(from.ip(), now, false));
                    }
                }
            } else if let IcmpV4Packet::Unreachable(what) = icmp {
                let pkt = match what {
                    icmp4::Unreachable::Net(pkt) => pkt,
                    icmp4::Unreachable::Host(pkt) => pkt,
                    icmp4::Unreachable::Protocol(pkt) => pkt,
                    icmp4::Unreachable::Port(pkt) => pkt,
                    icmp4::Unreachable::Other(_, pkt) => pkt,
                };

                if let Ok(key) = Probe::decode4(pkt) {
                    if let Some(tx) = state.sender(&key) {
                        let _ = tx.send(Echo(from.ip(), now, true));
                    }
                }
            } else if let IcmpV4Packet::EchoReply(echo) = icmp {
                let src = ip.source.into();
                let dst = ip.destination.into();
                let key = Key::ICMP(dst, src, echo.id);

                if let Some(tx) = state.sender(&key) {
                    let _ = tx.send(Echo(from.ip(), now, true));
                }
            }
        }
    }
}

async fn recv6(sock: Arc<RawSocket>, state: Arc<State>) -> Result<()> {
    let mut pkt = [0u8; 64];
    let mut ctl = [0u8; 64];

    loop {
        let iovec = &[IoSliceMut::new(&mut pkt)];
        let (n, from) = sock.recv_msg(iovec, Some(&mut ctl)).await?;

        let now = Instant::now();
        let pkt = IcmpV6Packet::try_from(&pkt[..n])?;

        if let IcmpV6Packet::HopLimitExceeded(pkt) = pkt {
            if let Ok(key) = Probe::decode6(pkt) {
                if let Some(tx) = state.sender(&key) {
                    let _ = tx.send(Echo(from.ip(), now, false));
                }
            }
        } else if let IcmpV6Packet::Unreachable(what) = pkt {
            let pkt = match what {
                icmp6::Unreachable::Address(pkt) => pkt,
                icmp6::Unreachable::Port(pkt) => pkt,
                icmp6::Unreachable::Other(_, pkt) => pkt,
            };

            if let Ok(key) = Probe::decode6(pkt) {
                if let Some(tx) = state.sender(&key) {
                    let _ = tx.send(Echo(from.ip(), now, false));
                }
            }
        } else if let IcmpV6Packet::EchoReply(echo) = pkt {
            let dst = CMsg::decode(&ctl).find_map(|msg| match msg {
                CMsg::Ipv6PktInfo(info) => Some(info.addr()),
                _ => None,
            });

            if let Some(dst) = dst {
                let dst = dst.into();
                let key = Key::ICMP(dst, from.ip(), echo.id);

                if let Some(tx) = state.sender(&key) {
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

const ICMP: u8 = IpNumber::Icmp as u8;
