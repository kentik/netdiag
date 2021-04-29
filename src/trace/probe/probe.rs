use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use anyhow::{anyhow, Error, Result};
use etherparse::{IpTrafficClass, Ipv4Header, Ipv6Header};
use super::{TCPv4, TCPv6, UDPv4, UDPv6};

#[derive(Debug)]
pub enum Probe {
    TCP(TCP),
    UDP(UDP),
}

#[derive(Debug)]
pub enum TCP {
    V4(TCPv4),
    V6(TCPv6),
}

#[derive(Debug)]
pub enum UDP {
    V4(UDPv4),
    V6(UDPv6),
}

#[derive(Copy, Clone, Debug)]
pub enum Protocol {
    TCP(u16),
    UDP(u16),
}

#[derive(Debug)]
pub struct Probes {
    proto: Protocol,
    src:   SocketAddr,
    dst:   IpAddr,
    value: u16,
}

pub const PORT_MIN: u16 = 33434;
pub const PORT_MAX: u16 = 65407;

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub enum Key {
    TCP(SocketAddr, IpAddr),
    UDP(SocketAddr, IpAddr),
}

impl Probe {
    pub fn decode4(pkt: &[u8]) -> Result<Key> {
        let (head, tail) = Ipv4Header::read_from_slice(pkt)?;
        match head.protocol {
            TCP   => Ok(TCPv4::decode(head, tail)?.key()),
            UDP   => Ok(UDPv4::decode(head, tail)?.key()),
            other => Err(anyhow!("unsupported protocol: {}", other)),
        }
    }

    pub fn decode6(pkt: &[u8]) -> Result<Key> {
        let (head, tail) = Ipv6Header::read_from_slice(pkt)?;
        match head.next_header {
            TCP   => Ok(TCPv6::decode(head, tail)?.key()),
            UDP   => Ok(UDPv6::decode(head, tail)?.key()),
            other => Err(anyhow!("unsupported protocol: {}", other)),
        }
    }

    pub fn encode<'a>(&self, buf: &'a mut [u8], ttl: u8) -> Result<&'a [u8]> {
        match self {
            Self::TCP(TCP::V4(tcp)) => tcp.encode(buf, ttl),
            Self::TCP(TCP::V6(tcp)) => tcp.encode(buf),
            Self::UDP(UDP::V4(udp)) => udp.encode(buf, ttl),
            Self::UDP(UDP::V6(udp)) => udp.encode(buf),
        }
    }

    pub fn dst(&self) -> SocketAddr {
        match self {
            Self::TCP(TCP::V4(tcp)) => tcp.dst.into(),
            Self::TCP(TCP::V6(tcp)) => tcp.dst.into(),
            Self::UDP(UDP::V4(udp)) => udp.dst.into(),
            Self::UDP(UDP::V6(udp)) => udp.dst.into(),
        }
    }

    pub fn key(&self) -> Key {
        match self {
            Self::TCP(TCP::V4(v4)) => Key::TCP(v4.src.into(), IpAddr::from(*v4.dst.ip())),
            Self::TCP(TCP::V6(v6)) => Key::TCP(v6.src.into(), IpAddr::from(*v6.dst.ip())),
            Self::UDP(UDP::V4(v4)) => Key::UDP(v4.src.into(), IpAddr::from(*v4.dst.ip())),
            Self::UDP(UDP::V6(v6)) => Key::UDP(v6.src.into(), IpAddr::from(*v6.dst.ip())),
        }
    }

    pub fn increment(&mut self) {
        match self {
            Self::TCP(TCP::V4(v4)) => v4.increment(),
            Self::TCP(TCP::V6(v6)) => v6.increment(),
            Self::UDP(UDP::V4(v4)) => v4.increment(),
            Self::UDP(UDP::V6(v6)) => v6.increment(),
        }
    }
}

impl Probes {
    pub fn new(proto: Protocol, src: IpAddr, dst: IpAddr, value: u16) -> Self {
        let src = match proto {
            Protocol::TCP(..) => SocketAddr::new(src, value),
            Protocol::UDP(..) => SocketAddr::new(src, value),
        };
        Self { proto, src, dst, value }
    }

    pub fn key(&self) -> Key {
        let Self { proto, src, dst, .. } = *self;
        match proto {
            Protocol::TCP(..) => Key::TCP(src, dst),
            Protocol::UDP(..) => Key::UDP(src, dst),
        }
    }

    pub fn probe(&self) -> Result<Probe> {
        let Self { proto, src, dst, .. } = *self;
        Ok(match proto {
            Protocol::TCP(port) => Probe::TCP(TCP::try_from((src, dst, port))?),
            Protocol::UDP(port) => Probe::UDP(UDP::try_from((src, dst, port))?),
        })
    }
}

impl Default for Protocol {
    fn default() -> Self {
        Self::UDP(PORT_MIN)
    }
}

impl From<TCPv4> for Probe {
    fn from(v4: TCPv4) -> Self {
        Probe::TCP(TCP::V4(v4))
    }
}

impl From<TCPv6> for Probe {
    fn from(v6: TCPv6) -> Self {
        Probe::TCP(TCP::V6(v6))
    }
}

impl From<UDPv4> for Probe {
    fn from(v4: UDPv4) -> Self {
        Probe::UDP(UDP::V4(v4))
    }
}

impl From<UDPv6> for Probe {
    fn from(v6: UDPv6) -> Self {
        Probe::UDP(UDP::V6(v6))
    }
}

impl TryFrom<(SocketAddr, IpAddr, u16)> for TCP {
    type Error = Error;

    fn try_from((src, dst, port): (SocketAddr, IpAddr, u16)) -> Result<Self, Self::Error> {
        match (src, dst) {
            (SocketAddr::V4(src), IpAddr::V4(dst)) => Ok(TCP::V4(TCPv4::new(src, sa4(dst, port)))),
            (SocketAddr::V6(src), IpAddr::V6(dst)) => Ok(TCP::V6(TCPv6::new(src, sa6(dst, port)))),
            _                                      => Err(invalid()),
        }
    }
}

impl TryFrom<(SocketAddr, IpAddr, u16)> for UDP {
    type Error = Error;

    fn try_from((src, dst, port): (SocketAddr, IpAddr, u16)) -> Result<Self, Self::Error> {
        match (src, dst) {
            (SocketAddr::V4(src), IpAddr::V4(dst)) => Ok(UDP::V4(UDPv4::new(src, sa4(dst, port)))),
            (SocketAddr::V6(src), IpAddr::V6(dst)) => Ok(UDP::V6(UDPv6::new(src, sa6(dst, port)))),
            _                                      => Err(invalid()),
        }
    }
}

fn sa4(addr: Ipv4Addr, port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(addr, port)
}

fn sa6(addr: Ipv6Addr, port: u16) -> SocketAddrV6 {
    SocketAddrV6::new(addr, port, 0, 0)
}

fn invalid() -> Error {
    anyhow!("mixed IPv4 and IPv6 addresses")
}

const TCP: u8 = IpTrafficClass::Tcp as u8;
const UDP: u8 = IpTrafficClass::Udp as u8;
