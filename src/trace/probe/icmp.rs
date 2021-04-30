use std::convert::{TryFrom, TryInto};
use std::io::{Cursor, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use anyhow::{Result, anyhow};
use etherparse::*;
use crate::icmp::{icmp4, icmp6};
use super::{Key, Probe};

#[derive(Debug)]
pub struct ICMPv4 {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub id:  u16,
    pub seq: u16,
}

#[derive(Debug)]
pub struct ICMPv6 {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub id:  u16,
    pub seq: u16,
}

impl ICMPv4 {
    pub fn new(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16) -> Self {
        Self { src, dst, id, seq }
    }

    pub fn decode(ip: Ipv4Header, tail: &[u8]) -> Result<Probe> {
        let src = Ipv4Addr::from(ip.source);
        let dst = Ipv4Addr::from(ip.destination);

        if tail.len() < icmp4::HEADER_SIZE {
            return Err(anyhow!("short buffer"));
        }

        let id  = u16::from_be_bytes(tail[4..6].try_into()?);
        let seq = u16::from_be_bytes(tail[6..8].try_into()?);

        Ok(Probe::from(ICMPv4 { src, dst, id, seq }))
    }

    pub fn encode<'a>(&self, buf: &'a mut [u8], ttl: u8) -> Result<&'a mut [u8]> {
        let mut buf = Cursor::new(buf);

        let src = self.src.octets();
        let dst = self.dst.octets();
        let len = u16::try_from(icmp4::HEADER_SIZE)?;

        let pkt = Ipv4Header::new(len, ttl, IpTrafficClass::Icmp, src, dst);
        pkt.write(&mut buf)?;

        let mut pkt = [0u8; icmp4::HEADER_SIZE];
        pkt[0..2].copy_from_slice(&[icmp4::ECHO_REQUEST, 0]);
        pkt[2..4].copy_from_slice(&0u16.to_be_bytes());
        pkt[4..6].copy_from_slice(&self.id.to_be_bytes());
        pkt[6..8].copy_from_slice(&self.seq.to_be_bytes());

        let cksum = icmp4::checksum(&pkt).to_be_bytes();
        pkt[2..4].copy_from_slice(&cksum);
        buf.write_all(&pkt)?;

        let n = usize::try_from(buf.position())?;

        Ok(&mut buf.into_inner()[..n])
    }

    pub fn key(&self) -> Key {
        let src = self.src.into();
        let dst = self.dst.into();
        Key::ICMP(src, dst, self.id)
    }

    pub fn increment(&mut self) {
        self.seq += 1;
    }
}

impl ICMPv6 {
    pub fn new(src: Ipv6Addr, dst: Ipv6Addr, id: u16, seq: u16) -> Self {
        Self { src, dst, id, seq }
    }

    pub fn decode(ip: Ipv6Header, tail: &[u8]) -> Result<Probe> {
        let src = Ipv6Addr::from(ip.source);
        let dst = Ipv6Addr::from(ip.destination);

        if tail.len() < icmp6::HEADER_SIZE {
            return Err(anyhow!("short buffer"));
        }

        let id  = u16::from_be_bytes(tail[4..6].try_into()?);
        let seq = u16::from_be_bytes(tail[6..8].try_into()?);

        Ok(Probe::from(ICMPv6 { src, dst, id, seq }))
    }

    pub fn encode<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8]> {
        let mut buf = Cursor::new(buf);

        let mut pkt = [0u8; icmp6::HEADER_SIZE];
        pkt[0..2].copy_from_slice(&[icmp6::ECHO_REQUEST, 0]);
        pkt[2..4].copy_from_slice(&0u16.to_be_bytes());
        pkt[4..6].copy_from_slice(&self.id.to_be_bytes());
        pkt[6..8].copy_from_slice(&self.seq.to_be_bytes());
        buf.write_all(&pkt)?;

        let n = usize::try_from(buf.position())?;

        Ok(&mut buf.into_inner()[..n])
    }

    pub fn key(&self) -> Key {
        let src = self.src.into();
        let dst = self.dst.into();
        Key::ICMP(src, dst, self.id)
    }

    pub fn increment(&mut self) {
        self.seq += 1;
    }
}
