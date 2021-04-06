use std::convert::{TryFrom, TryInto};
use anyhow::{anyhow, Error};

pub const HEADER_SIZE: usize = 8;

pub const UNREACHABLE:   u8 = 1;
pub const TIME_EXCEEDED: u8 = 3;
pub const ECHO_REQUEST:  u8 = 128;
pub const ECHO_REPLY:    u8 = 129;

#[derive(Debug)]
pub enum IcmpV6Packet<'a> {
    Unreachable(Unreachable<'a>),
    EchoRequest(Echo<'a>),
    EchoReply(Echo<'a>),
    HopLimitExceeded(&'a [u8]),
    ReassemblyTimeExceeded(&'a [u8]),
    Other(u8, u8, &'a [u8]),
}

#[derive(Debug)]
pub struct Echo<'a> {
    pub id:   u16,
    pub seq:  u16,
    pub data: &'a [u8]
}

#[derive(Debug)]
pub enum Unreachable<'a> {
    Address(&'a [u8]),
    Port(&'a [u8]),
    Other(u8, &'a [u8]),
}

impl<'a> TryFrom<&'a [u8]> for IcmpV6Packet<'a> {
    type Error = Error;

    fn try_from(slice: &'a [u8]) -> Result<Self, Self::Error> {
        if slice.len() < HEADER_SIZE {
            return Err(anyhow!("invalid slice"));
        }

        let kind = slice[0];
        let code = slice[1];
        let rest = &slice[4..];

        Ok(match (kind, code) {
            (UNREACHABLE,   _) => IcmpV6Packet::Unreachable((code, rest).try_into()?),
            (TIME_EXCEEDED, 0) => IcmpV6Packet::HopLimitExceeded(&rest[4..]),
            (TIME_EXCEEDED, 1) => IcmpV6Packet::ReassemblyTimeExceeded(&rest[4..]),
            (ECHO_REQUEST,  0) => IcmpV6Packet::EchoRequest(rest.try_into()?),
            (ECHO_REPLY,    0) => IcmpV6Packet::EchoReply(rest.try_into()?),
            _                  => IcmpV6Packet::Other(kind, code, rest),
        })
    }
}

impl<'a> TryFrom<&'a [u8]> for Echo<'a> {
    type Error = Error;

    fn try_from(slice: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            id:   u16::from_be_bytes(slice[0..2].try_into()?),
            seq:  u16::from_be_bytes(slice[2..4].try_into()?),
            data: &slice[4..]
        })
    }
}

impl<'a> TryFrom<(u8, &'a [u8])> for Unreachable<'a> {
    type Error = Error;

    fn try_from((code, slice): (u8, &'a [u8])) -> Result<Self, Self::Error> {
        let data = &slice[4..];
        Ok(match code {
            3 => Unreachable::Address(data),
            4 => Unreachable::Port(data),
            c => Unreachable::Other(c, data),
        })
    }
}
