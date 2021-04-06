use std::io::Cursor;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use anyhow::Result;
use etherparse::*;
use super::Probe;

#[derive(Debug)]
pub struct UDPv4 {
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
}

#[derive(Debug)]
pub struct UDPv6 {
    pub src: SocketAddrV6,
    pub dst: SocketAddrV6,
}

impl UDPv4 {
    pub fn new(src: SocketAddrV4, dst: SocketAddrV4) -> Self {
        Self { src, dst }
    }

    pub fn decode(ip: Ipv4Header, tail: &[u8]) -> Result<Probe> {
        let src = Ipv4Addr::from(ip.source);
        let dst = Ipv4Addr::from(ip.destination);

        let pkt = UdpHeaderSlice::from_slice(&tail)?;
        let src = SocketAddrV4::new(src, pkt.source_port());
        let dst = SocketAddrV4::new(dst, pkt.destination_port());

        Ok(Probe::from(UDPv4 { src, dst }))
    }

    pub fn encode<'a>(&self, buf: &'a mut [u8], ttl: u8) -> Result<&'a [u8]> {
        let mut buf = Cursor::new(buf);

        let src = self.src.ip().octets();
        let dst = self.dst.ip().octets();

        let pkt = PacketBuilder::ipv4(src, dst, ttl);
        let pkt = pkt.udp(self.src.port(), self.dst.port());

        let n = pkt.size(0);
        pkt.write(&mut buf, &[])?;

        Ok(&buf.into_inner()[..n])
    }

    pub fn increment(&mut self) {
        self.dst.set_port(self.dst.port() + 1);
    }
}

impl UDPv6 {
    pub fn new(src: SocketAddrV6, dst: SocketAddrV6) -> Self {
        Self { src, dst }
    }

    pub fn decode(ip: Ipv6Header, tail: &[u8]) -> Result<Probe> {
        let src = Ipv6Addr::from(ip.source);
        let dst = Ipv6Addr::from(ip.destination);

        let pkt = UdpHeaderSlice::from_slice(&tail)?;
        let src = SocketAddrV6::new(src, pkt.source_port(), 0, 0);
        let dst = SocketAddrV6::new(dst, pkt.destination_port(), 0, 0);

        Ok(Probe::from(UDPv6 { src, dst }))
    }

    pub fn encode<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8]> {
        let mut buf = Cursor::new(buf);

        let src = self.src.port();
        let dst = self.dst.port();
        let pkt = UdpHeader::without_ipv4_checksum(src, dst, 0)?;

        pkt.write(&mut buf)?;
        let n = buf.position() as usize;

        Ok(&buf.into_inner()[..n])
    }

    pub fn increment(&mut self) {
        self.dst.set_port(self.dst.port() + 1);
    }
}
