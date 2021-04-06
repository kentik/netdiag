use std::io::Cursor;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use anyhow::{anyhow, Result};
use etherparse::*;

#[derive(Debug)]
pub enum Probe {
    V4(ProbeV4),
    V6(ProbeV6),
}

#[derive(Debug)]
pub struct ProbeV4 {
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub seq: u32,
}

#[derive(Debug)]
pub struct ProbeV6 {
    pub src: SocketAddrV6,
    pub dst: SocketAddrV6,
    pub seq: u32,
}

impl Probe {
    pub fn new(src: SocketAddr, dst: SocketAddr, seq: u32) -> Result<Self> {
        let probe4  = |src, dst| Probe::V4(ProbeV4 { src, dst, seq });
        let probe6  = |src, dst| Probe::V6(ProbeV6 { src, dst, seq });
        let invalid = || anyhow!("mixed IPv4 and IPv6 addresses");

        match (src, dst) {
            (SocketAddr::V4(src), SocketAddr::V4(dst)) => Ok(probe4(src, dst)),
            (SocketAddr::V6(src), SocketAddr::V6(dst)) => Ok(probe6(src, dst)),
            _                                          => Err(invalid()),
        }
    }

    pub fn src(&self) -> SocketAddr {
        match self {
            Self::V4(v4) => SocketAddr::V4(v4.src),
            Self::V6(v6) => SocketAddr::V6(v6.src),
        }
    }

    pub fn dst(&self) -> SocketAddr {
        match self {
            Self::V4(v4) => SocketAddr::V4(v4.dst),
            Self::V6(v6) => SocketAddr::V6(v6.dst),
        }
    }

    pub fn seq(&self) -> u32 {
        match self {
            Self::V4(v4) => v4.seq,
            Self::V6(v6) => v6.seq,
        }
    }
}

impl ProbeV4 {
    pub fn encode<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8]> {
        let mut buf = Cursor::new(buf);

        let src = self.src.ip().octets();
        let dst = self.dst.ip().octets();
        let win = 5840;

        let pkt = PacketBuilder::ipv4(src, dst, 64);
        let pkt = pkt.tcp(self.src.port(), self.dst.port(), self.seq, win).syn();

        let n = pkt.size(0);
        pkt.write(&mut buf, &[])?;

        Ok(&buf.into_inner()[..n])
    }
}

impl ProbeV6 {
    pub fn encode<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8]> {
        let mut buf = Cursor::new(buf);

        let src = self.src.port();
        let dst = self.dst.port();
        let win = 5840;

        let mut pkt = TcpHeader::new(src, dst, self.seq, win);
        pkt.syn = true;

        pkt.write(&mut buf)?;
        let n = buf.position() as usize;

        Ok(&buf.into_inner()[..n])
    }
}
