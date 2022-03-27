use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use anyhow::{anyhow, Result};
use futures::{pin_mut, StreamExt};
use gumdrop::Options;
use tokio::net::lookup_host;
use tokio::time::sleep;
use netdiag::{Bind, Protocol, Tracer, trace::Node};

#[derive(Debug, Options)]
pub struct Args {
    #[options()]                help:   bool,
    #[options(default = "UDP")] proto:  String,
    #[options()]                port:   u16,
    #[options(default = "4")]   count:  usize,
    #[options(default = "30")]  limit:  u8,
    #[options(default = "500")] delay:  u64,
    #[options(default = "250")] expiry: u64,
    #[options(free, required)]  host:   String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse_args_default_or_exit();
    let Args { proto, port, count, limit, delay, expiry, host, .. } = args;

    env_logger::init();

    let proto = match proto.to_uppercase().as_str() {
        "ICMP"            => Protocol::ICMP,
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

    let tracer = Tracer::new(&bind).await?;
    let source = tracer.reserve(proto, addr).await?;

    let mut done  = false;
    let mut ttl   = 1;
    let mut probe = source.probe()?;

    while !done && ttl <= limit {
        let mut nodes = HashMap::<IpAddr, Vec<String>>::new();

        let stream = tracer.probe(&mut probe, ttl, expiry);
        let stream = stream.take(count);
        pin_mut!(stream);

        while let Some(Ok(node)) = stream.next().await {
            if let Node::Node(_, ip, rtt, last) = node {
                let rtt = format!("{:>0.2?}", rtt);
                nodes.entry(ip).or_default().push(rtt);
                done = last || ip == addr;
            }

            sleep(delay).await;
        }

        print(&nodes, ttl, count);

        ttl += 1;
    }

    Ok(())
}

fn print(nodes: &HashMap<IpAddr, Vec<String>>, ttl: u8, probes: usize) {
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
