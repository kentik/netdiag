use std::convert::{TryFrom, TryInto};
use anyhow::Error;

use crate::ping::TOKEN_SIZE;

#[derive(Debug)]
pub struct Echo<'a> {
    pub id:    u16,
    pub seq:   u16,
    pub token: &'a [u8],
    pub data:  &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for Echo<'a> {
    type Error = Error;

    fn try_from(slice: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            id:   u16::from_be_bytes(slice[0..2].try_into()?),
            seq:  u16::from_be_bytes(slice[2..4].try_into()?),
            token: &slice[4..TOKEN_SIZE + 4],
            data: &slice[4..],
        })
    }
}
