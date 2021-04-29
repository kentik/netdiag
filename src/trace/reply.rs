use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum Node {
    Node(u8, IpAddr, Duration, bool),
    None(u8)
}

#[derive(Clone, Debug)]
pub struct Echo(pub IpAddr, pub Instant, pub bool);
