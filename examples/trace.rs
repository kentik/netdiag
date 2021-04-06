use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use anyhow::{anyhow, Result};
use gumdrop::Options;
use tokio::net::{lookup_host, UdpSocket};
use tokio::time::sleep;
use netdiag::{Bind, Protocol, Tracer, trace::{Probe, Node}};

#[derive(Debug, Options)]
pub struct Args {
    #[options()]                help:   bool,
    #[options(default = "UDP")] proto:  String,
    #[options()]                port:   u16,
    #[options(default = "4")]   count:  usize,
    #[options(default = "30")]  limit:  usize,
    #[options(default = "500")] delay:  u64,
    #[options(default = "250")] expiry: u64,
    #[options(free, required)]  host:   String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse_args_default_or_exit();
    let Args { proto, port, count, limit, delay, expiry, host, .. } = args;

    let proto = match proto.to_uppercase().as_str() {
        "TCP" if port > 0 => Protocol::TCP(port),
        "UDP" if port > 0 => Protocol::UDP(port),
        _                 => Protocol::default(),
    };

    let delay  = Duration::from_millis(delay);
    let expiry = Duration::from_millis(expiry);

    let addr = format!("{}:0", host);
    let addr = lookup_host(&addr).await?.next().ok_or_else(|| {
        anyhow!("invalid target")
    })?.ip();

    println!("tracing {} ({})", host, addr);

    let bind = Bind::default();
    let src  = source(&bind, addr).await?;

    let tracer = Tracer::new(&bind).await?;

    let mut done = false;
    let mut ttl  = 1;

    while !done && ttl <= limit {
        let mut nodes = HashMap::<IpAddr, Vec<String>>::new();
        let mut probe = Probe::new(proto, src, addr)?;

        for _ in 0..count {
            let node = tracer.probe(&probe, ttl as u8, expiry).await?;

            if let Node::Node(_, ip, rtt, last) = node {
                let rtt = format!("{:>0.2?}", rtt);
                nodes.entry(ip).or_default().push(rtt);
                done = last || ip == addr;
            }

            probe.increment();

            sleep(delay).await;
        }

        print(&nodes, ttl, count);

        ttl += 1;
    }

    Ok(())
}

fn print(nodes: &HashMap<IpAddr, Vec<String>>, ttl: usize, probes: usize) {
    let mut count = 0;

    let mut output = nodes.iter().map(|(node, rtt)| {
        count += rtt.len();
        let node = node.to_string();
        let rtt  = rtt.join(", ");
        (node, rtt)
    }).collect::<Vec<_>>();

    if count < probes {
        let node = "* ".repeat(probes - count);
        let rtt  = String::new();
        output.push((node, rtt));
    }

    for (n, (node, rtt)) in output.iter().enumerate() {
        match n {
            0 => println!("[{:>3}] {:32} {}", ttl, node, rtt),
            _ => println!("[{:>3}] {:32} {}", "",  node, rtt),
        }
    }
}

async fn source(bind: &Bind, dst: IpAddr) -> Result<SocketAddr> {
    let sock = match dst {
        IpAddr::V4(_) => UdpSocket::bind(bind.sa4()),
        IpAddr::V6(_) => UdpSocket::bind(bind.sa6()),
    }.await?;

    sock.connect(SocketAddr::new(dst, 1234)).await?;

    Ok(sock.local_addr()?)
}
