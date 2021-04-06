use std::cmp::min;
use std::io::Cursor;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use anyhow::Result;
use etherparse::*;
use super::Probe;

#[derive(Debug)]
pub struct TCPv4 {
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub seq: u32,
}

#[derive(Debug)]
pub struct TCPv6 {
    pub src: SocketAddrV6,
    pub dst: SocketAddrV6,
    pub seq: u32,
}

impl TCPv4 {
    pub fn new(src: SocketAddrV4, dst: SocketAddrV4) -> Self {
        Self { src, dst, seq: 1 }
    }

    pub fn decode(ip: Ipv4Header, tail: &[u8]) -> Result<Probe> {
        let src = Ipv4Addr::from(ip.source);
        let dst = Ipv4Addr::from(ip.destination);

        let mut buf = [80u8; 64];
        let n = min(buf.len(), tail.len());
        buf[..n].copy_from_slice(&tail[..n]);

        let pkt = TcpHeaderSlice::from_slice(&buf)?;
        let src = SocketAddrV4::new(src, pkt.source_port());
        let dst = SocketAddrV4::new(dst, pkt.destination_port());
        let seq = pkt.sequence_number();

        Ok(Probe::from(TCPv4 { src, dst, seq }))
    }

    pub fn encode<'a>(&self, buf: &'a mut [u8], ttl: u8) -> Result<&'a [u8]> {
        let mut buf = Cursor::new(buf);

        let src = self.src.ip().octets();
        let dst = self.dst.ip().octets();
        let win = 5840;

        let pkt = PacketBuilder::ipv4(src, dst, ttl);
        let pkt = pkt.tcp(self.src.port(), self.dst.port(), self.seq, win).syn();

        let n = pkt.size(0);
        pkt.write(&mut buf, &[])?;

        Ok(&buf.into_inner()[..n])
    }

    pub fn increment(&mut self) {
        self.seq += 1;
    }
}

impl TCPv6 {
    pub fn new(src: SocketAddrV6, dst: SocketAddrV6) -> Self {
        Self { src, dst, seq: 1 }
    }

    pub fn decode(ip: Ipv6Header, tail: &[u8]) -> Result<Probe> {
        let src = Ipv6Addr::from(ip.source);
        let dst = Ipv6Addr::from(ip.destination);

        let mut buf = [80u8; 64];
        let n = min(buf.len(), tail.len());
        buf[..n].copy_from_slice(&tail[..n]);

        let pkt = TcpHeaderSlice::from_slice(&buf)?;
        let src = SocketAddrV6::new(src, pkt.source_port(), 0, 0);
        let dst = SocketAddrV6::new(dst, pkt.destination_port(), 0, 0);
        let seq = pkt.sequence_number();

        Ok(Probe::from(TCPv6 { src, dst, seq }))
    }

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

    pub fn increment(&mut self) {
        self.seq += 1;
    }
}
