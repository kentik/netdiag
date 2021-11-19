use std::convert::TryInto;
use std::io::Error;
use std::mem::{zeroed, size_of};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::AsRawFd;
use anyhow::Result;
use libc::{self, sockaddr};
use tokio::net::UdpSocket;

pub struct RouteSocket {
    sock: UdpSocket
}

impl RouteSocket {
    pub async fn new(bind: SocketAddr) -> Result<Self> {
        let sock = UdpSocket::bind(bind).await?;
        Ok(Self { sock })
    }

    pub async fn source(&mut self, addr: SocketAddr) -> Result<IpAddr> {
        if cfg!(target_os = "linux") {
            reset(&self.sock)?;
        }
        self.sock.connect(addr).await?;
        Ok(self.sock.local_addr()?.ip())
    }
}

fn reset(sock: &UdpSocket) -> Result<()> {
    unsafe {
        let fd   = sock.as_raw_fd();
        let addr = zeroed();
        let len  = size_of::<sockaddr>().try_into()?;
        match libc::connect(fd, &addr, len) {
            0 => Ok(()),
            _ => Err(Error::last_os_error().into())
        }
    }
}
