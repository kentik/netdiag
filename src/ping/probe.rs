use std::array::TryFromSliceError;
use std::convert::{TryFrom, TryInto};
use std::net::IpAddr;
use anyhow::{anyhow, Result};
use rand::random;
use crate::icmp::{icmp4, icmp6};

#[derive(Debug)]
pub struct Probe {
    pub addr:  IpAddr,
    pub id:    u16,
    pub seq:   u16,
    pub token: Token,
}

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct Token([u8; 16]);

impl Probe {
    pub fn new(addr: IpAddr, id: u16, seq: u16) -> Self {
        let token = Token(random());
        Self { addr, id, seq, token }
    }

    pub fn encode<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8]> {
        let (request, mut n) = match self.addr {
            IpAddr::V4(_) => (icmp4::ECHO_REQUEST, icmp4::HEADER_SIZE),
            IpAddr::V6(_) => (icmp6::ECHO_REQUEST, icmp6::HEADER_SIZE),
        };

        n += self.token.0.len();

        if buf.len() < n {
            return Err(anyhow!("short buffer"));
        }

        buf[0..2].copy_from_slice(&[request, 0]);
        buf[2..4].copy_from_slice(&0u16.to_be_bytes());
        buf[4..6].copy_from_slice(&self.id.to_be_bytes());
        buf[6..8].copy_from_slice(&self.seq.to_be_bytes());
        buf[8..n].copy_from_slice(&self.token.0);

        Ok(&mut buf[0..n])
    }
}

impl TryFrom<&[u8]> for Token {
    type Error = TryFromSliceError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(buf.try_into()?))
    }
}
