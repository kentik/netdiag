use std::net::*;

#[derive(Clone, Debug, Default)]
pub struct Bind {
    sa4: Option<SocketAddrV4>,
    sa6: Option<SocketAddrV6>,
}

impl Bind {
    pub fn sa4(&self) -> SocketAddr {
        SocketAddr::V4(self.sa4.unwrap_or_else(|| {
            let addr = Ipv4Addr::new(0, 0, 0, 0);
            let port = 0;
            SocketAddrV4::new(addr, port)
        }))
    }

    pub fn sa6(&self) -> SocketAddr {
        SocketAddr::V6(self.sa6.unwrap_or_else(|| {
            let addr = Ipv6Addr::from([0u8; 16]);
            let port = 0;
            SocketAddrV6::new(addr, port, 0, 0)
        }))
    }

    pub fn set(&mut self, addr: IpAddr) {
        match addr {
            IpAddr::V4(ip) => self.sa4 = Some(SocketAddrV4::new(ip, 0)),
            IpAddr::V6(ip) => self.sa6 = Some(SocketAddrV6::new(ip, 0, 0, 0)),
        }
    }
}
