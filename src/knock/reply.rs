use std::time::Instant;
use etherparse::TcpHeader;

#[derive(Debug)]
pub struct Reply {
    pub head: TcpHeader,
    pub when: Instant,
}

impl Reply {
    pub fn new(head: TcpHeader, when: Instant) -> Self {
        Self { head, when }
    }
}
